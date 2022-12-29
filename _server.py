from _common import *
import socketserver

Online = []
lock = Lock()

class ThreadedTCPRequestHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.sock = MsgSocket(self.request)
        
        try:
            self.authenticate()

            while raw := self.sock.get():
                #if not raw: continue
                m = Message().decrypt(raw)
                # forward messages
                for E in Online:
                    pk = next(iter(E))
                    if m.to == pk:
                        mx = Message(self.my_entity, m.conts, i=m.id).encrypt()
                        try:
                            E[pk].put(mx)
                        except Exception as e:
                            if not e in (BrokenPipeError, ConnectionResetError, OSError):
                                print("---- sub send ERROR: ")
                                traceback.print_exc()
                print(Online)
        except:
            print("main send: ")
            traceback.print_exc()
        finally:
            self.cleanup_entity()
            print("closing")


    def cleanup_entity(self) -> None:
        for E in Online:
            pk = next(iter(E))
            if (E[pk].sock.fileno()) < 0:
                print("closing dead socket")
            if pk == self.my_entity:
                # Only close the currently active socket, or any missed closed ones.
                if (E[pk].sock == self.request):
                    Online.remove(E)
    
    def count_entity(self, entity_pk: PublicKey) -> int:
        count = 0
        for E in Online:
            pk = next(iter(E))
            if pk == entity_pk:
                count += 1
        return count

    def authenticate(self) -> (None or bool):
        session_sk = PrivateKey.generate()

        # Do a DH key exchange to create a secure session key.
        session_secret = Box(session_sk, PublicKey(self.sock.get())).shared_key()
        self.sock.put(session_sk.public_key.encode())

        self.sock.session_key = session_secret

        # Get the entity's auth information
        entity_proof_raw = self.sock.get()
        entity_proof = Message().decrypt(entity_proof_raw)
        shared_secret = Box(testing_server_entity.sk, entity_proof.pk).shared_key()
        
        # TODO: catch decrypt error on failure
        entity_proof = Message(key=shared_secret).decrypt(entity_proof_raw)

        # Validate entity
        if entity_proof.pk == PublicKey(entity_proof.conts):
            self.sock.key = shared_secret

            # Make the Entity accessible to others
            if self.count_entity(entity_proof.pk) < server_config_max_logins*2:
                self.my_entity = entity_proof.pk
                Online.append({self.my_entity: self.sock})

                print("entity auth success", Entity(pk=entity_proof.pk).encode())
                #print("initial_secret is", Base64Encoder.encode(shared_secret))
                #print("session_secret is", Base64Encoder.encode(session_secret))
            else:
                print("too many logins for: ", Entity(pk=entity_proof.pk).encode())
                # disconnect entity because they are already logged in
                return True
        else:
            print("entity auth fail", Entity(pk=entity_proof.pk).encode())
            return True

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    # Since IPV6 > IPV4!
    address_family = socket.AF_INET6

if __name__ == "__main__":
    server = ThreadedTCPServer((testing_server_entity.ip, testing_server_entity.port), ThreadedTCPRequestHandler)
    with server:
        print("Serving on", server.server_address)
        
        server.serve_forever()
        server.shutdown()
