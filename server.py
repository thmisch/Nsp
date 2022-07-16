"""
Copyright (C) 2022 themisch

This file is part of Nsc.
Nsc is free software: you can redistribute it and/or modify it under the terms
of the GNU General Public License as published by the Free Software Foundation,
either version 3 of the License, or (at your option) any later version.

Nsc is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
without even the implied warranty of MERCHANTABILITY or
FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
details.

You should have received a copy of the GNU General Public License along with Nsc.
If not, see <https://www.gnu.org/licenses/>.
"""

from common import *
import socketserver

cache = list()

class Scp:
    def __init__(self, peer):
        self.peer = peer
        self.conn = True
        self.verified_names = list()

    def verify_name(self, obj):
        peer_name = obj.get("PubKey")
        # TODO: add check for nothin here
        peer_exchange_key = PublicKey(peer_name)
        exchange_key = PrivateKey.generate()

        box = Box(exchange_key, peer_exchange_key)
        Socket(self.peer).put(Asm.user_packet(exchange_key.public_key.encode()))

        # If the peer has the private key for the provided public key, then
        # a key exchange is possible. If not then we know the peer is trying to
        # get unwanted access to another peers data.
        res = Socket(self.peer).get()
        typ = res.get("Type") if type(res) == dict else None
        if typ == "MSG" and res.get("Message"):
            msg = box.decrypt(res.get("Message"))
            if msg == peer_name:
                self.verified_names.append(peer_name)
                cache.append({peer_name: self.peer})
                return
        self.end()

    # try to find potentially bad packets, which could crash the reciepients
    # client.
    def check_packet(self, packet):
        typ = packet["Type"]
        if typ == "KEX":
            # if a bad key was provided, this will crash the current server
            # thread, disconnecting the attacker.
            PublicKey(packet.get("PubExKey"))
            
    def handle(self):
        sent = False
        res = Socket(self.peer).get()

        # disconnect the peer when invalid data was recieved.
        if not res:
            print("ending")
            self.end()
            return

        if res.get("Type") in ("KEX", "MSG"):
            # Only verified names are allowed send messages
            if (not res["From"]["PubKey"] in self.verified_names) or self.check_packet(res):
                print("unverified_peer or bad packet")
                self.end()
                return
            # start from the back of the cache, to allow newer connections
            # to recieve the message instead.
            for user in cache:
                recipient = next(iter(user))
                if res["To"]["PubKey"] == recipient:
                    Socket(user[recipient]).put(res)
                    sent = True

            # notify the peer if the message couldn't be sent to `To`
            if not sent:
                Socket(self.peer).put(Err("offline"))

        elif res.get("Type") == "USR":
            self.verify_name(res)
        print(res)

    def end(self):
        self.conn = False
        print("DISCONNECTed:", self.peer)
        for addr in self.verified_names:
            e = {addr: self.peer}
            if e in cache:
                cache.remove(e)
                print("peer removed from cache")

class TLServer(socketserver.TCPServer):
    def __init__(self, server_address, RequestHandlerClass, bind_and_activate=True):
        socketserver.TCPServer.__init__(
            self, server_address, RequestHandlerClass, bind_and_activate
        )

        # self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        # self.context.load_cert_chain('keys/cert.pem', 'keys/key.pem')
        # self.socket = self.context.wrap_socket(self.socket, server_side=True)

class ThreadingTLServer(socketserver.ThreadingMixIn, TLServer):
    pass

class TLSRequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        proto = Scp(self.request)
        while proto.conn:
            # TODO: use try to catch errors later
            try:
                proto.handle()
            except Exception as e:
                proto.end()
                print("unhandled err:\n\n", e)

def main():
    server = ThreadingTLServer(CON, TLSRequestHandler)
    ip, port = server.server_address
    print("Serving on: {}:{}".format(ip, port))
    server.serve_forever()

if __name__ == "__main__":
    main()
