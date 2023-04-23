# Nsp v1.0
# New simple protocol (https://github.com/thmisch/Nsp)

# Depends: pynacl

# Simply import this file in your applications, by downloading, or by using
# git submodules.

import socket
import msgpack
import struct
from threading import Thread, Lock
from enum import Enum, auto
from queue import Queue

from nacl.encoding import URLSafeBase64Encoder
from nacl.public import PrivateKey, Box, PublicKey
from nacl.secret import SecretBox
from nacl.exceptions import CryptoError


# https://stackoverflow.com/questions/17667903/python-socket-receive-large-amount-of-data
# Simplify sending and recieving of messages
class MsgSocket:
    def __init__(
        self, sockfd: socket.socket, key: bytes = None, session_key: bytes = None
    ) -> None:
        self.sock = sockfd
        self.session_key = key
        self.key = key

    def put(self, msg: bytes) -> None:
        # encrypt if available yet
        for key in (self.session_key, self.key):
            if key:
                msg = SecretBox(key).encrypt(msg)

        # Prefix each message with a 4-byte length (network byte order)
        msg = struct.pack(">I", len(msg)) + msg
        self.sock.sendall(msg)

    def get(self) -> bytes:
        def recvall(sock, n) -> bytes:
            # Helper function to recv n bytes or return None if EOF is hit
            data = bytearray()
            while len(data) < n:
                packet = sock.recv(n - len(data))
                if not packet:
                    return None
                data.extend(packet)
            return bytes(data)

        # Read message length and unpack it into an integer
        raw_msglen = recvall(self.sock, 4)
        if not raw_msglen:
            return None
        msglen = struct.unpack(">I", raw_msglen)[0]
        # Read the message data
        msg = recvall(self.sock, msglen)

        if msg:
            for key in (self.key, self.session_key):
                if key:
                    msg = SecretBox(key).decrypt(msg)

        return msg


# Some (important) types for the default subprotocols.
class MessageType(Enum):
    Default = auto()
    KexInitial = auto()
    KexReply = auto()


class Message:
    def __init__(
        self,
        X: PublicKey = None,
        Y: bytes = None,
        key: bytes = None,
        key2: bytes = None,
        typ: MessageType = MessageType.Default,
    ) -> None:
        self.x = X
        self.y = Y
        self.alias()

        self.key = key
        self.key2 = key2
        self.type = typ

    def alias(self):
        self.frm = self.to = self.pk = self.x
        self.conts = self.y

    def encrypt(self, no_type: bool = False) -> bytes:
        self.alias()

        if no_type:
            tmp_y = self.y
        else:
            tmp_y = msgpack.dumps([self.type.value, self.y])

        for key in (self.key, self.key2):
            if key:
                tmp_y = SecretBox(key).encrypt(tmp_y)

        return msgpack.dumps([self.x.encode(), tmp_y])

    def decrypt(self, encoded: bytes, only_x: bool = False):
        if not encoded:
            return

        self.x, self.y = msgpack.loads(encoded)
        self.x = PublicKey(self.x)
        if only_x:
            return self.x

        for key in (self.key2, self.key):
            if key:
                self.y = SecretBox(key).decrypt(self.y)

        # This is needed for when we can't decrypt the content.
        try:
            self.type, self.y = msgpack.loads(self.y)
            self.type = MessageType(self.type)
        except:
            pass

        self.alias()
        return self


# An Nsp Entity can be a client or a server. This structure includes
# all the required information to connect to and verify a server, and
# to locate and verify clients: either the servers' ip address and port
# or the server ip address and port that the client's usually connected to
# and their public keys.
class Entity:
    def __init__(
        self,
        ip: str = None,
        port: int = None,
        pk: PublicKey = None,
        sk: PrivateKey = None,
    ) -> None:
        self.ip, self.port, self.pk, self.sk = ip, port, pk, sk
        # if (not pk) and sk:
        #     self.pk = sk.public_key

    # En/De-code Entity in the NspEntity format.
    def encode(self) -> str:
        return URLSafeBase64Encoder.encode(
            msgpack.dumps([self.ip, self.port, self.pk.encode()])
        ).decode()

    def decode(self, encoded: str):
        self.ip, self.port, self.pk = msgpack.loads(
            URLSafeBase64Encoder.decode(encoded.encode())
        )
        self.pk = PublicKey(self.pk)
        return self


class KexAuthError(Exception):
    pass


class ThreadEnd:
    pass


class Nsp:
    def __init__(self, myself: Entity, server: Entity) -> None:
        self.myself = myself
        self.server = server

        # TODO: LOAD this from database on close
        # AND RELAUNCH all the required threads to get things going
        self.kex = {}  # {entity: [Message(), Message(), ...]}

        # TODO: LOAD UNSENT MESSAGES INTO THESE ON STARTUP
        self.incoming, self.outgoing = Queue(), Queue()
        self.threads = [Thread(target=self.getloop), Thread(target=self.putloop)]
        self.lock = Lock()
        [x.start() for x in self.threads]

    def kexfor(self, pk):
        with self.lock:
            if not pk in self.kex:
                self.kex[pk] = []

    def kexcheck(self, pk: bytes or PublicKey):
        with self.lock:
            if not pk in self.kex or not len(self.kex[pk]):
                # TODO: ADD TO UNTRUSTED; AND HANDLE ERRORS
                raise TypeError(f"{pk} is lying, or your memory corrupted.")

    def getloop(self) -> None:
        sock = self.initsock()
        while True:
            raw_m = sock.get()
            if not raw_m:
                break
            frm = Message().decrypt(raw_m, only_x=True)
            shared_secret = Box(self.myself.sk, frm).shared_key()
            m = Message(key2=shared_secret).decrypt(raw_m)

            match m.type:
                # SOMEONE wants send us a MESSAGE.
                # So we send a KexReply
                case MessageType.KexInitial:
                    # TODO: maybe WAIT, until WE've ASKED THE USER if its okay
                    # to reply

                    self.kexfor(m.frm)
                    msg = Message(m.frm, key=PrivateKey.generate())

                    kex_msg = Message(
                        m.frm,
                        msg.key.public_key.encode(),
                        key2=shared_secret,
                        typ=MessageType.KexReply,
                    )

                    msg.key = Box(msg.key, PublicKey(m.conts)).shared_key()

                    with self.lock:
                        self.kex[m.frm].append(msg)
                    sock.put(kex_msg.encrypt())

                # We should be the sender
                case MessageType.KexReply:
                    self.kexcheck(m.to)

                    with self.lock:
                        msg = self.kex[m.to].pop(0)

                    msg.key = Box(msg.key, PublicKey(m.conts)).shared_key()
                    msg.key2 = shared_secret
                    sock.put(msg.encrypt())

                # The type is Default, since the content AND type is encrypted with msg.key,
                # which we don't have yet, and so decrypt will fail -> Default Type will be selected.
                case MessageType.Default:
                    self.kexcheck(m.to)

                    with self.lock:
                        msg = self.kex[m.to].pop(0)

                    md = Message(key=msg.key, key2=shared_secret).decrypt(raw_m)
                    self.incoming.put(md)
                    # TODO: maybe handle nacl.exceptions.CryptoError:

                case _:
                    raise TypeError(
                        f"{m.to} used an unsupported message type: {m.type}"
                    )

    def putloop(self) -> None:
        sock = self.initsock()
        while True:
            msg = self.outgoing.get()
            if type(msg) == ThreadEnd:
                break
            self.kexfor(msg.to)

            kex_msg = Message(
                msg.to,
                msg.key.public_key.encode(),
                key2=msg.key2,
                typ=MessageType.KexInitial,
            )

            with self.lock:
                self.kex[msg.to].append(msg)
            sock.put(kex_msg.encrypt())

    # Establish a secure connection with the given server entity over an insecure channel.
    def initsock(self) -> MsgSocket:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        sock.connect((self.server.ip, self.server.port))

        # start handshake
        session_sk = PrivateKey.generate()

        sock = MsgSocket(sock)

        # Do a DH key exchange to create a secure session key.
        sock.put(session_sk.public_key.encode())
        session_secret = Box(session_sk, PublicKey(sock.get())).shared_key()
        sock.session_key = session_secret

        # Proof for the server that you are the one claiming to be
        shared_secret = Box(self.myself.sk, self.server.pk).shared_key()
        my_proof = Message(
            self.myself.pk, self.myself.pk.encode(), key=shared_secret
        )

        sock.put(my_proof.encrypt())
        sock.key = shared_secret

        return sock

    def send(self, to: PublicKey, message: bytes) -> None:
        m = Message(
            to,
            message,
            key=PrivateKey.generate(),
            key2=Box(self.myself.sk, to).shared_key(),
        )
        self.outgoing.put(m)
