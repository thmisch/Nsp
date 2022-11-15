from collections import namedtuple

from _common import *
# TODO: INCOMING, OUTGOING QUEUES

class Errors(Enum):
    AuthFailed = 1

# Connect to server
# AUTH procedure:
#  CLIENT: send [Apk, Apk encrypted with shared secret of Ask and Spk]
#  SERVER: decrypt res[1] with shared secret of Ssk and res[0]
#          if no errors, and decrypted res[1] == res[0], mark client as logged in
#          else disconnect client.
#          send Spk encrypted with shared secret of Ssk and res[0]
#  CLIENT: decrypt with shared secret of Ask and Spk
#          if result == Spk, stay connected.
#          else disconnect
# This shared secret is now used by both parties to en/de-crypt everything that's going in and out.
#

# FROM/TO, MSG
# [PK, MSG]
# If you recieve a packet, the first entry is always FROM
# If you send a packet, put the one your sending TO first.
# This is what would A sends: 
#  [Bpk, Arpk encrypted with Ask&Bpk]
# This is what the server would then send to B:
#  [Apk, Arpk encrypted woth Ask&Bpk]
#  If B can decrypt [1] with Bsk & [0], they can trust A, 
# and have the rpk A's gonna use for their message



# EXAMPLE connection trace
'''
A -> S: [Apk, Apk encrypted with Ask & Spk]

A and S define shared_scecret to Ask & Spk or Ssk & Apk

# This message isn't really needed, as when the client  
S -> A: [encrypted with shared_secret [Spk, Spk encrypted with shared_secret]]

S -> A: []
[session_encryption]:
'''

# The Nsc client API

#  connect to a server
#  authenticate
#  listen for messages, send messages
class NsClientApi:
    def __init__(self, myself: Entity) -> None:
        self.myself = myself

    def initiate_server_connection(self, server: Entity) -> (MsgSocket or int):
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        sock.connect((server.ip, server.port))

        sock = MsgSocket(sock) 

        return self.authenticate(sock, server)

    def authenticate(self, sock: MsgSocket, server: Entity) -> bool:
        shared_secret = Box(self.myself.sk, server.pk).shared_key() 

        # If the server can decrypt this sucessfully, it knows you are you. 
        my_proof = Message(self.myself.pk, self.myself.pk.encode(), key=shared_secret)
        sock.put(my_proof.encrypt())

        # If you can decrypt the servers message contents sucessfully, you now they're legit 
        sock.key = shared_secret
        server_proof = Message(key=shared_secret).decrypt(sock.get())
        if server.pk == server_proof.pk == PublicKey(server_proof.conts):
            my_session_sk = PrivateKey.generate()

            # do a key exchange, for the session key
            sock.put(Message(my_session_sk.public_key).encrypt())
            server_session_pk = Message().decrypt(sock.get()).pk
            shared_session_key = Box(my_session_sk, server_session_pk).shared_key()

            print("session_secret is", Base64Encoder.encode(shared_session_key))

            # Encrypt twice
            sock.session_key = shared_session_key
            sock.put(msgpack.dumps(True))
            return sock
        else:
            print("server auth fail")
            socket.close(sock.sock)
            return Errors.AuthFailed

#my_sk = PrivateKey.generate()
my_sk = PrivateKey(b'\xc9\x1c4a-;\xbf`\x87n#+\x87\xa6V\xef\xeaNKtCx\x81N{\xf3\xf8+\xba\xe4\xe2!')
my_pk = my_sk.public_key


myself = Entity(testing_server_entity.ip, testing_server_entity.port, pk=my_pk, sk=my_sk)

clnt = NsClientApi(myself)
server_connection = clnt.initiate_server_connection(testing_server_entity)
time.sleep(1)
