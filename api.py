from common import *

class KexAuthError(Exception): pass
class ThreadEnd(): pass

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

    def kexcheck(self, pk):
        with self.lock:
            if not pk in self.kex or not len(self.kex[pk]):
                # TODO: ADD TO UNTRUSTED; AND HANDLE ERRORS
                raise TypeError(f"{m.to} is lying, or your memory corrupted.")

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
                    msg = Message(m.frm, 
                                  key=PrivateKey.generate()
                    )
                    
                    kex_msg = Message(m.frm, 
                                      msg.key.public_key.encode(),
                                      key2=shared_secret, 
                                      typ=MessageType.KexReply
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

                # The type is Default, since the content is encrypted with msg.key,
                # which we don't have yet, and so decrypt will crash.
                case MessageType.Default:
                    self.kexcheck(m.to)

                    with self.lock:
                        msg = self.kex[m.to].pop(0)

                    md = Message(key=msg.key, key2=shared_secret).decrypt(raw_m)
                    self.incoming.put(md)
                    # TODO: maybe handle nacl.exceptions.CryptoError:

                case _:
                    raise TypeError(f"{m.to} used an unsupported message type: {m.type}")

    def putloop(self) -> None:
        sock = self.initsock()
        while True:
            msg = self.outgoing.get()
            if type(msg) == ThreadEnd:
                break
            self.kexfor(msg.to)

            kex_msg = Message(msg.to, 
                          msg.key.public_key.encode(), 
                          key2=msg.key2, 
                          typ=MessageType.KexInitial
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
        my_proof = Message(self.myself.pk, self.myself.pk.encode(), key=shared_secret)

        sock.put(my_proof.encrypt())
        sock.key = shared_secret

        return sock

    def send(self, to: PublicKey, message: bytes) -> None:
        m = Message(
            to,
            message,
            key=PrivateKey.generate(),
            key2=Box(self.myself.sk, to).shared_key()
        )
        self.outgoing.put(m)
