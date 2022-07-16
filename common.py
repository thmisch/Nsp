import struct, zlib
from os.path import exists
from queue import Queue
import time
import json
import msgpack

class conf:
    HOST = "87.187.26.105"
    PORT = 4011
    ADINFO = (HOST, PORT)
    MAX_MSG_SIZE =  50 * (1024 ** 2)
    def update_server_address():
        conf.ADINFO = conf.HOST, conf.PORT
    DB = 'db.json'

# generate an error message dict
class Error:
    def __init__(self, error_msg):
        self.error_msg = error_msg
    def gen(self):
        return {
                'ERR': self.error_msg.upper()
                }
class Message:
    def __init__(self, message):
        self.msg = message
    
    def Err(self):
        return {
            'Err': self.msg.upper()
        }

    def Ok(self):
        return {
            'Okay': self.msg.upper()
        }

class msg:
    def __init__(self, socket):
        self.socket = socket

    def checksize(self, byte_data):
        if byte_data:
            if len(byte_data) < conf.MAX_MSG_SIZE:
                return True

    def send(self, data):
        # https://stackoverflow.com/questions/17667903/python-socket-receive-large-amount-of-data
        def send_msg(sock, msg):
            # Prefix each message with a 4-byte length (network byte order)
            msg = struct.pack('>I', len(msg)) + msg
            sock.sendall(msg)
        def encode(data):
            byte_data = msgpack.packb(data)
            #obj = zlib.compress(byte_data)
            #byte_data = json.dumps(data).encode()
            return byte_data
        self.socket.sendall(encode(data))
        # send_msg(self.socket, encode(data))

    def recieve(self):
        def recv_msg(sock):
            def recvall(sock, n):
                # Helper function to recv n bytes or return None if EOF is hit
                data = bytearray()
                while len(data) < n:
                    packet = sock.recv(n - len(data))
                    if not packet:
                        return None
                    data.extend(packet)
                return data
            # Read message length and unpack it into an integer
            raw_msglen = recvall(sock, 4)
            if not raw_msglen:
                return None
            msglen = struct.unpack('>I', raw_msglen)[0]
            # Read the message data
            return recvall(sock, msglen)
        def decode(byte_data):
            # raw = zlib.decompress(byte_data)
            #obj = json.loads(byte_data.decode())
            obj = msgpack.unpackb(byte_data)
            return obj

        # result = recv_msg(self.socket)
        result = self.socket.recv()
        if self.checksize(result):
            return decode(result)
