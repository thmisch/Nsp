import socket
import msgpack
import struct
from threading import Thread, Lock
from enum import Enum, auto
from queue import Queue
from sys import getsizeof

from nacl.encoding import URLSafeBase64Encoder as Base64Encoder
from nacl.public import PrivateKey, Box, PublicKey
from nacl.secret import SecretBox
from nacl.exceptions import CryptoError
import nacl.pwhash
import nacl.utils
import time
import secrets
import traceback

# https://stackoverflow.com/questions/17667903/python-socket-receive-large-amount-of-data
# Simplify sending and recieving of messages
class MsgSocket:
    def __init__(self, sockfd: socket.socket, key: bytes = None, session_key: bytes = None) -> None:
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

    def encrypt(self, no_type:bool = False) -> bytes:
        self.alias()

        if no_type:
            tmp_y = self.y
        else:
            tmp_y = msgpack.dumps([self.type.value, self.y])

        for key in (self.key, self.key2):
            if key:
                tmp_y = SecretBox(key).encrypt(tmp_y)

        return msgpack.dumps([self.x.encode(), tmp_y])

    def decrypt(self, encoded: bytes, only_x: bool=False):
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
        return Base64Encoder.encode(msgpack.dumps([self.ip, self.port, self.pk.encode()])).decode()

    def decode(self, encoded: str):
        self.ip, self.port, self.pk = msgpack.loads(Base64Encoder.decode(encoded.encode()))
        self.pk = PublicKey(self.pk)
        return self


# TODO: Implement another, better way to set the server's private key.
testing_server_sk = PrivateKey(
    b"\xcc\xb7`\xd4V\x1cvu\rg\xcd\xdd\xbdM\x06\xa3\x9d\xf8\x10\x1e|\x074\x13\xaa$\x1d-\x19\xber\xfd"
)
# testing_server_sk = PrivateKey.generate()
testing_server_pk = testing_server_sk.public_key
testing_server_entity = Entity("::1", 11742, testing_server_pk, testing_server_sk)
