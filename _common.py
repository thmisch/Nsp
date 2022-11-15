import socket
from nacl.public import PrivateKey, Box, PublicKey
from nacl.secret import SecretBox
from nacl.encoding import URLSafeBase64Encoder as Base64Encoder
import nacl.pwhash
import nacl.utils
import msgpack
from enum import Enum
import struct
import threading
from queue import Queue
import nacl.hash
import time
from sys import getsizeof

# def deep_getsizeof(o, ids): https://code.tutsplus.com/tutorials/understand-how-much-memory-your-python-objects-use--cms-25609

# How many times the same entity can be logged in at the same time
server_config_max_logins = 3

# https://stackoverflow.com/questions/17667903/python-socket-receive-large-amount-of-data

# Simplify sending and recieving of messages
class MsgSocket:
    def __init__(self, sockfd: socket.socket, key: bytes=None, session_key: bytes=None) -> None:
        self.sock = sockfd
        self.session_key = key
        self.key = key

    def put(self, msg: bytes) -> None:
        if self.key: msg = SecretBox(self.key).encrypt(msg)
        if self.session_key: msg = SecretBox(self.session_key).encrypt(msg)

        # Prefix each message with a 4-byte length (network byte order)
        msg = struct.pack('>I', len(msg)) + msg
        self.sock.sendall(msg)

    def get(self) -> bytes:
        def recvall(sock, n) -> bytes:
            # Helper function to recv n bytes or return None if EOF is hit
            data = bytearray()
            while len(data) < n:
                packet = sock.recv(n - len(data))
                if not packet:
                    return None
                data.extend(packet)
            return bytes(data)

        # Read message length and unpack it into an integer
        raw_msglen = recvall(self.sock, 4)
        if not raw_msglen:
            return None
        msglen = struct.unpack('>I', raw_msglen)[0]
        # Read the message data
        msg = recvall(self.sock, msglen)
        if self.session_key: msg = SecretBox(self.session_key).decrypt(msg)
        if self.key: msg = SecretBox(self.key).decrypt(msg)
        return msg

# The default and only message type in Nsc:
#  [DEST, MSG] or just [X, Y]
# X is always a public key, thats automagically getting en/decoded on .encrypt/.decrypt
# X is either your own public key in AUTH, the recipients or the senders key in any other case.
# Y can contain any binary data, in AUTH this data is a your encrypted public key, on all other
# occasions Y contains the message. 
class Message:
    def __init__(self, X: PublicKey=None, Y: bytes=None, key: bytes=None) -> None:
        self.x = X
        self.y = Y
        self.alias()

        self.key = key

    def alias(self):
        self.frm = self.to = self.pk = self.x
        self.conts = self.y 

    def encrypt(self) -> bytes:
        Y = SecretBox(self.key).encrypt(self.y) if self.key else self.y
        return msgpack.dumps([self.x.encode(), Y])

    def decrypt(self, encoded: bytes):
        self.x, self.y = msgpack.loads(encoded)
        self.x = PublicKey(self.x)
        if self.key: 
            self.y = SecretBox(self.key).decrypt(self.y)
        self.alias()
        return self

# An Nsc Entity can be a client or a server. This structure includes
# all the required information to connect and verify a server, and 
# to locate and verify clients: either the server's ip address and port 
# or the clients' server ip address and port, and their public keys.
class Entity:
    def __init__(self, ip: str=None, port: int=None, pk: PublicKey=None, sk: PrivateKey=None) -> None:
        self.ip, self.port, self.pk, self.sk = ip, port, pk, sk
        #if (not pk) and sk:
        #    self.pk = sk.public_key

    # En/De-code the Entity in Nsc's standard format.
    def encode(self) -> str:
        return Base64Encoder.encode(msgpack.dumps([self.ip, self.port, self.pk.encode()])).decode()
    
    def decode(self, encoded: str):
        self.ip, self.port, self.pk = msgpack.loads(Base64Encoder.decode(encoded.encode()))
        self.pk = PublicKey(self.pk)
        return self

# TODO: Implement another, better way to set the server's private key.
testing_server_sk = PrivateKey(b'\xcc\xb7`\xd4V\x1cvu\rg\xcd\xdd\xbdM\x06\xa3\x9d\xf8\x10\x1e|\x074\x13\xaa$\x1d-\x19\xber\xfd')
#testing_server_sk = PrivateKey.generate()
testing_server_pk = testing_server_sk.public_key
testing_server_entity = Entity("::1", 10349, testing_server_pk, testing_server_sk)
