from _common import *
import socketserver
import time
Online = []

class ThreadedTCPRequestHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.sock = MsgSocket(self.request)
        self.my_entity = None

        while raw := self.sock.get():
            if not self.my_entity:
                if self.authenticate(raw): break
            # TODO: Handle messages
            print(Online)

        self.cleanup_entity()
        print("closing")

    def cleanup_entity(self) -> None:
        for E in Online:
            pk = next(iter(E))
            if pk == self.my_entity:
                if (E[pk] == self.request) or (E[pk].fileno()) < 0:
                    Online.remove(E)
    
    def count_entity(self, entity_pk: PublicKey) -> int:
        count = 0
        for E in Online:
            pk = next(iter(E))
            if pk == entity_pk:
                count += 1
        return count

    def authenticate(self, raw: bytes) -> (None or bool):
        entity_proof = Message().decrypt(raw)
        shared_secret = Box(testing_server_entity.sk, entity_proof.pk).shared_key()
        print("initial_secret is", Base64Encoder.encode(shared_secret))
        entity_proof = Message(key=shared_secret).decrypt(raw)

        if entity_proof.pk == PublicKey(entity_proof.conts):
            my_session_sk = PrivateKey.generate()
            print("client auth success", Entity(pk=entity_proof.pk).encode())

            self.sock.key = shared_secret
            # Authenticate to the client, as they did for you.
            my_proof = Message(testing_server_entity.pk, testing_server_entity.pk.encode(), key=shared_secret)
            self.sock.put(my_proof.encrypt())


            # do a key exchange to get a session key
            entity_session_pk = Message().decrypt(self.sock.get()).pk
            self.sock.put(Message(my_session_sk.public_key).encrypt())
            shared_session_key = Box(my_session_sk, entity_session_pk).shared_key()

            self.sock.session_key = shared_session_key
            data = msgpack.loads(self.sock.get())
            print(data)

            # Make the Entity accessible to others
            if self.count_entity(entity_proof.pk) < server_config_max_logins:
                self.my_entity = entity_proof.pk.encode()
                Online.append({self.my_entity: self.request})
            else:
                # disconnect entity because they are already logged in
                return True
        else:
            print("client auth fail", Entity(pk=entity_proof.pk).encode())
            return True

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    # The newer, the better.
    address_family = socket.AF_INET6

if __name__ == "__main__":
    server = ThreadedTCPServer((testing_server_entity.ip, testing_server_entity.port), ThreadedTCPRequestHandler)
    with server:
        print("Serving on", server.server_address)
        
        server.serve_forever()
        server.shutdown()
