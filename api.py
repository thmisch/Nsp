from common import *

'''
EXAMPLE connection trace of an AUTH procedure

first we do a keyexchange
A -> S: [A_random_pk]
S -> A: [S_random_pk]

A & S derive session_secret, that is used from now on as the FIRST encryption layer.

A gives their pk, and their pk encrypted with the shared secret between them and S.
If S can decrypt this, it means A is legit since they must have had their secret key.

A -> S: [Apk, Apk encrypted with Ask & Spk]

A & S derive shared_secret from Ask & Spk or Ssk & Apk

shared_secret is from now on used as the SECOND encryption layer 
In the next messages, if we are able to decrypt them, we know whether the server is legit or not.

'''

# The Nsc client API

#  connect to a server
#  authenticate
#  listen for messages, send messages
lock = Lock()

class KexAuthError(Exception): pass

class NsClientApi:
    def __init__(self, myself: Entity, server: Entity) -> None:
        self.myself = myself
        self.server = server

        # TODO: LOAD this from database on close
        # AND RELAUNCH all the required threads to get things going
        self.kex = {} # {entity: [Message(), Message(), ...]} 

        # TODO: LOAD UNSENT MESSAGES INTO THESE ON STARTUP
        self.i, self.o = Queue(), Queue()
        self.threads = [Thread(target=self.getloop), Thread(target=self.putloop)]
        [x.start() for x in self.threads]

    def getloop(self) -> None:
        sock = self.initsock()
        while True:
            raw_m = sock.get()
            #if not raw_m: continue

            m = Message().decrypt(raw_m)
            shared_secret = Box(self.myself.sk, m.pk).shared_key()
            m = Message(key2=shared_secret).decrypt(raw_m)
            
            try:
                if not m.frm in self.kex: self.kex[m.frm] = []

                # If this raises an error, we've just found out that we've recieved the actual content of a message
                pk = PublicKey(m.conts)

                # 1. A reply to a keyexchange I initiated, so I'm the sender in that case
                # 2. Or a i'm the replier to a keyexchange, reply with another one,
                # to recieve a message from the sender

                # Option 1, i'm the sender, and the message I just recieved is a reply to my Keyexchange 
                sender = False
                for i, msg in enumerate(self.kex[m.frm]):
                    # find the right message I want to send by looking at the ID of the reply keyexchange
                    if m.id == msg.id:
                        print("I'M SENDER")
                        sender = True
                        try:
                            msg.key = Box(msg.key, pk).shared_key()
                            msg.key2 = shared_secret
                            with lock:
                                self.kex[m.frm].remove(msg)
                            sock.put(msg.encrypt())
                            break

                        except nacl.exceptions.TypeError:
                            print("----------------TYPE ERROR######")
                            print("usually means you've got the same msg.id for 2 msgs or more")

                        except:
                            traceback.print_exc()

                # I'm not the sender, I'm the reciever AND reply with a keyexchange.
                # TODO: CHECK DUPLICATE MESSAGES USING ID
                if not sender:
                    msg = Message(m.frm, key=PrivateKey.generate())
                    tmp_msg = Message(m.frm, msg.key.public_key.encode(), key2=shared_secret, i=m.id)
                    msg.key = Box(msg.key, pk).shared_key()
                    #with lock:
                    self.kex[m.frm].append(msg)
                    
                    sock.put(tmp_msg.encrypt())

            # The message contents isn't just a public exchange key. 
            # So it must be the ACTUAL message content.
            except nacl.exceptions.ValueError:
                # find the right decryption key
                for i, msg in enumerate(self.kex[m.frm]):
                    try:
                        md = Message(key=msg.key, key2=shared_secret).decrypt(raw_m)
                        print("decrypt FIN", md.conts)
                        with lock:
                            self.kex[m.frm].remove(msg)
                        break
                    except nacl.exceptions.CryptoError:
                        pass

    # This loop repeadly goes through active messages to send, and sends a 
    # keyexchange message to the other entity.
    def putloop(self) -> None:
        sock = self.initsock()
        while True:
            for entity in self.kex.keys():
                with lock:
                    for m in self.kex[entity]:
                        if type(m.key) != bytes:
                            tmp_msg = Message(m.to, m.key.public_key.encode(), key2=m.key2, i=m.id)
                            sock.put(tmp_msg.encrypt())
                time.sleep(0.1)

    def initsock(self) -> MsgSocket:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        sock.connect((self.server.ip, self.server.port))
        return self.authenticate(MsgSocket(sock))

    # Establish a secure connection with the given server entity over an insecure channel
    def authenticate(self, socket: MsgSocket) -> None:
        session_sk = PrivateKey.generate()

        # Do a DH key exchange to create a secure session key.
        socket.put(session_sk.public_key.encode())
        session_secret = Box(session_sk, PublicKey(socket.get())).shared_key()

        socket.session_key = session_secret

        # Proof for the server that you are the one claiming to be
        shared_secret = Box(self.myself.sk, self.server.pk).shared_key()
        my_proof = Message(self.myself.pk, self.myself.pk.encode(), key=shared_secret)

        socket.put(my_proof.encrypt()) 
        socket.key = shared_secret
        print("USED KEY: ", socket.key)

        return socket

    def sendto(self, to_pk: PublicKey, message: bytes) -> None:
        m = Message(to_pk, message, key=PrivateKey.generate(), key2=Box(self.myself.sk, to_pk).shared_key(), 
            i=secrets.randbelow(2**63))
        if not m.to in self.kex: self.kex[m.to] = []
        self.kex[m.to].append(m)

my_sk = PrivateKey.generate()
other_sk = PrivateKey(b'\xc9\x1c4a-;\xbf`\x87n#+\x87\xa6V\xef\xeaNKtCx\x81N{\xf3\xf8+\xba\xe4\xe2!')
my_pk = my_sk.public_key

myself = Entity(testing_server_entity.ip, testing_server_entity.port, pk=my_pk, sk=my_sk)
other = Entity(testing_server_entity.ip, testing_server_entity.port, pk=other_sk.public_key, sk=other_sk)

if argv[1] == "SENDER":
    api = NsClientApi(myself, testing_server_entity)
    for i in range(2000):
        api.sendto(other.pk, "HIYA, TESTING! {d}".format(d=i).encode())
    api.sendto(other.pk, "ALL WORKS FINE!! {d}".format(d=0).encode())
else:
    api = NsClientApi(other, testing_server_entity)
