from collections import namedtuple

from _common import *
# TODO: INCOMING, OUTGOING QUEUES

# EXAMPLE connection trace
'''
AUTH procedure
A -> S: [Apk, Apk encrypted with Ask & Spk]

A & S derive shared_scecret from Ask & Spk or Ssk & Apk

A & S perform a key exchange to get a shared session key
  A -> S: [encrypted with shared_secret [A_random_pk, None]]
  S -> A: [encrypted with shared_secret [S_random_pk, None]]

A & S derive shared_session_secret from A_random_sk & S_random_pk or S_random_sk & A_random_pk

From now on messages will be encrypted with both keys, because why not.
If someone were to crack the session key, they'd also need to crack another key.
(Just to get the metadata, no message contents)

'''

# The Nsc client API

#  connect to a server
#  authenticate
#  listen for messages, send messages

class ServerAuthError(Exception): pass

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
 
        # From now on use the unique shared secret between you and the server
        # as a first encryption layer
        sock.key = shared_secret

        try:
            my_session_sk = PrivateKey.generate()

            # do a key exchange, for the session key
            sock.put(Message(my_session_sk.public_key).encrypt())
            server_session_pk = Message().decrypt(sock.get()).pk
            shared_session_secret = Box(my_session_sk, server_session_pk).shared_key()

            # Use the session secret as a second layer for security
            sock.session_key = shared_session_secret

            sock.put(msgpack.dumps(["Bester chat, 100% sicher und simple!"]))
            return sock

        except CryptoError:
            raise ServerAuthError

#my_sk = PrivateKey.generate()
my_sk = PrivateKey(b'\xc9\x1c4a-;\xbf`\x87n#+\x87\xa6V\xef\xeaNKtCx\x81N{\xf3\xf8+\xba\xe4\xe2!')
my_pk = my_sk.public_key


myself = Entity(testing_server_entity.ip, testing_server_entity.port, pk=my_pk, sk=my_sk)

clnt = NsClientApi(myself)
server_connection = clnt.initiate_server_connection(testing_server_entity)
