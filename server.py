import socket, socketserver
import threading
import ssl

from common import *
from crypt import *

cache = list()

class Scp:
    def __init__(self, socket):
        self.socket = socket
        self.m = msg(self.socket)
        self.conn = True

    def verify_name(self, usr):
        return Crypto.verify(usr.get('PubKey'), usr.get('Signature'), usr.get('Username'))

    def entry(self):
        res = self.m.recieve()
        if res.get('Type') == 'USR':
            for user in cache:
                socket = next(iter(user))
                #verified = Crypto.verify(
                #        PubSwap.pem_to_obj(user[socket]['PubKey']),
                #        res['Signature'],
                #        res['Username']
                #)
                #if verified:
                #    print('USER ALREADY LOGGED IN')
                #    return self.end()
                if res['Signature'] == user[socket]['Signature']:
                    print('USER WITH SAME SIGNATURE -> DISCONNECT')
                    return self.end()
            cache.append(
                    {self.socket: res}
                    )
        else:
            return self.end()
        return True

    def handle(self):
        found = False
        res = self.m.recieve()
        if not res:
            self.end()
        elif res.get('Type') in ('KEX', 'MSG'):
            for user in cache:
                socket = next(iter(user))

                verified = Crypto.verify(
                        PubSwap.pem_to_obj(user[socket]['PubKey']),
                        res['To']['Signature'],
                        res['To']['Username']
                )
                if verified:
                    msg(socket).send(res)
                    self.m.send(Message('suc').Ok())
                    print(res)
                    found = True
            if not found:
                self.m.send(Message('usr_offline').Err())

    def end(self):
        self.conn = False
        for user in cache:
            if user.get(self.socket):
                cache.remove(user)
        print('DISCONNECTed: ', self.socket)
        return False

class TLServer(socketserver.TCPServer):
    def __init__(self, server_address, RequestHandlerClass, bind_and_activate=True):
        socketserver.TCPServer.__init__(self, server_address, RequestHandlerClass, bind_and_activate)

        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain('keys/cert.pem', 'keys/key.pem')
        self.socket = self.context.wrap_socket(self.socket, server_side=True)

class ThreadingTLServer(socketserver.ThreadingMixIn, TLServer): 
    pass

class TLSRequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        proto = Scp(self.request)
        try:
            if not proto.entry():
                return proto.end()
            while proto.conn: 
                proto.handle()
        finally:
            proto.end()

def main():
    server = ThreadingTLServer(conf.ADINFO, TLSRequestHandler)
    ip, port = server.server_address
    print("Serving on: {}:{}".format(ip, port))
    server.serve_forever()

if __name__ == "__main__":
    main()