from common import *
import socketserver
import threading

online_lock = threading.Lock()
Online = set()

class Config:
    # How many times the same entity can be logged in at the same time on the same server
    max_logins = 3


class Client:
    def __init__(self, socket, pk: PublicKey = None) -> None:
        self.sock: MsgSocket = socket
        self.pk = pk


class ThreadedTCPRequestHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.client = Client(MsgSocket(self.request))

        try:
            self.authenticate()

            while m := Message().decrypt(self.client.sock.get()):
                with online_lock:
                    for peer in Online:
                        if m.to == peer.pk:
                            #m.frm = self.client.pk
                            mx = Message(self.client.pk, m.conts).encrypt(no_type=True)
                            try:
                                #peer.sock.put(m.encrypt(no_type=True))
                                peer.sock.put(mx)
                            except Exception as e:
                                traceback.print_exc()

                print(Online)
        except:
            traceback.print_exc()
        finally:
            self.cleanup_client()
            print("--" * 40, "closing")
            with online_lock:
                print(Online)

    def cleanup_client(self) -> None:
        if self.client.pk:
            with online_lock:
                if self.client in Online:
                    Online.remove(self.client)

    def count_pk_online(self, pk: PublicKey = None) -> int:
        with online_lock:
            return sum(1 for other in Online if other.pk == pk)

    def authenticate(self) -> (None or bool):
        session_sk = PrivateKey.generate()

        # Do a DH key exchange to create a secure session key.
        session_secret = Box(session_sk, PublicKey(self.client.sock.get())).shared_key()
        self.client.sock.put(session_sk.public_key.encode())

        self.client.sock.session_key = session_secret

        # Get the client's auth information
        client_proof_raw = self.client.sock.get()

        client_pk = Message().decrypt(client_proof_raw, only_x=True)

        shared_secret = Box(testing_server_entity.sk, client_pk).shared_key()

        # TODO: catch decrypt error on failure
        client_proof = Message(key=shared_secret).decrypt(client_proof_raw)

        # Validate client
        if client_proof.pk == PublicKey(client_proof.conts):
            self.client.sock.key = shared_secret

            # Make the Entity accessible to others
            # *2 since each client is connected with 2 sockets
            if self.count_pk_online(client_proof.pk) < Config.max_logins * 2:
                # Set the clients public key
                self.client.pk = client_proof.pk

                with online_lock:
                    Online.add(self.client)

                print("client auth success", Entity(pk=self.client.pk).encode())
                # print("initial_secret is", Base64Encoder.encode(shared_secret))
                # print("session_secret is", Base64Encoder.encode(session_secret))
            else:
                print("too many logins for: ", Entity(pk=self.client.pk).encode())
                # disconnect client because they are already logged in
                return True
        else:
            print("client auth fail ", Entity(pk=self.client.pk).encode())
            return True


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    address_family = socket.AF_INET6

    def server_bind(self):
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(self.server_address)


if __name__ == "__main__":
    server = ThreadedTCPServer(
        (testing_server_entity.ip, testing_server_entity.port),
        ThreadedTCPRequestHandler,
    )
    with server:
        print("Serving on", server.server_address)

        server.serve_forever()
        server.shutdown()
