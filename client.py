from os import remove, makedirs
from os.path import exists
from sys import stdout, argv
from pathlib import Path

from xdg import xdg_data_home
from database import *
from queue import Queue
from common import *
import time      
from copy import deepcopy

Incoming, BackBurner = Queue(), Queue()
kex_cache = list()
# Convert nonces around, probably certificates will be used instead
class Nonce:
    def get(obj):
        if type(obj) == bytes:
            obj = Nonce.decode(obj)
        elif type(obj) == int:
            obj = Nonce.encode(obj)
        return obj

    def decode(obj):
        return int.from_bytes(obj, byteorder='big')
    def encode(obj):
        return obj.to_bytes(Box.NONCE_SIZE, byteorder='big')

# create and/or decrypt the database 
class Login:
    def __init__(self, pw, path):
        self.pw = pw
        self.path = Path(xdg_data_home(), 'nsc' + path)

        self.salt_path = str(Path(self.path, 'salt'))
        self.db_path = str(Path(self.path, 'db'))

        if not exists(self.path):
            makedirs(self.path)
            if not exists(self.salt_path):
                open(self.salt_path, 'a').close()
            self.create_new_creds()
        else:
            self.load_creds()

    # derive a new key from the provided password
    # which will be used for the encryption of the database.
    def open_db(self, salt):
        key = nacl.pwhash.scrypt.kdf(
            SecretBox.KEY_SIZE,
            self.pw.encode(),
            salt,
            # opslimit is static here, since if it would randomly change in the
            # future, the database couldn't be decrypted.
            opslimit=1398187,
            memlimit=nacl.pwhash.scrypt.MEMLIMIT_INTERACTIVE
        )
        self.db = PersistentDict(self.db_path, key)

    def create_new_creds(self):
        salt = nacl.utils.random(nacl.pwhash.scrypt.SALTBYTES)
        self.open_db(salt)

        # generate a new key, save it in the encrypted database
        sk = PrivateKey.generate()
        self.db['sk'] = sk
        self.db['pk'] = sk.public_key

        self.db['used_nonces'] = list()

        # save the salt
        with open(self.salt_path, 'wb') as f:
            f.write(salt)
        self.db.sync()

    def load_creds(self):
        with open(self.salt_path, 'rb') as f:
            salt = f.read()
            self.open_db(salt)
class Msg:
    def __init__(self):
        self.exchange_key = PrivateKey.generate()

    def recipient(self, senders_kex):
        self.kex_packet = Asm.kex_packet(
            self.exchange_key.public_key.encode(),
            Asm.from_to(
                senders_kex['To'], 
                senders_kex['From']
            )
        )
        self.box = Box(self.exchange_key, PublicKey(senders_kex['PubExKey']))
        self.sent = False

    def sender(self, from_to, message):
        self.kex_packet = Asm.kex_packet(
            self.exchange_key.public_key.encode(),
            from_to
        )
        self.message = message
        self.sent = True

class Connection:
   def __init__(self):
        # x = self.server_login(db['sk'])
        threading.Thread(target=self.BgGet, args=(None,)).start()
        threading.Thread(target=self.BgPut, args=(None,)).start()

   def BgGet(self, non):
        global db, kex_cache
        sock = self.server_login(db['sk'])
       
        while True:
            res = Socket(sock).get()
            typ = type(res) == dict
            sent = False
            if typ and res.get('Type') == 'KEX':
                for kex in kex_cache:
                    r = next(iter(kex))
                    m = kex[r]
                    if r == res['From']['PubKey'] and m.sent:
                        print('sender')
                        box = Box(m.exchange_key, PublicKey(res['PubExKey']))
                        msg = box.encrypt(m.message)
                        kex_cache.remove(kex)
                        Socket(sock).put(Asm.msg_packet(msg, Asm.from_to(res['To'], res['From'])))
                        x = Socket(sock).get()
                        print('sender status', x)
                        print(kex_cache)
                        sent = True
                        break
                if not sent:
                    # reply with another kex
                    m = Msg()
                    m.recipient(res)
                    kex_cache.append({res['From']['PubKey']: m})
                    Socket(sock).put(m.kex_packet)
                    x = Socket(sock).get()
                    print('reciever reply with kex', x)
            elif typ and res.get('Type') == 'MSG':
                # asm db structures
                for kex in kex_cache:
                    m = kex.get(res['From']['PubKey'])   
                    if m:
                        msg = m.box.decrypt(res['Message'])
                        print(msg)
                        kex_cache.remove(kex)
                        print(kex_cache)
                        break

   def BgPut(self, non):
        global db, kex_cache
        sock = self.server_login(db['sk'])
        while True:
            obj = Incoming.get()
            kex_cache.append({obj.kex_packet['To']['PubKey']: obj})
            Socket(sock).put(obj.kex_packet)
            x = Socket(sock).get()
            print("send status", x)

    # login the `key` on the server and prove that you're the owner of it.
   def server_login(self, key):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, int())
        sock.connect(CON)
        
        # do the key exchange
        public_key = key.public_key.encode()
        Socket(sock).put(Asm.user_packet(public_key))
        server_exchange_key = PublicKey(Socket(sock).get()['PubKey'])
        
        # encrypt and send the the public key to the server
        box = Box(key, server_exchange_key)
        msg = box.encrypt(public_key)
        Socket(sock).put(Asm.msg_packet(msg, dict()))
        return sock

class Client:
    def __init__(self, pw = 'XXX'):
        global db
        db = Login(pw, argv[1]).db
        threading.Thread(target=Connection).start()
        print(db['pk'].encode(B64Encoder))

        my_usr_pkt = Asm.user_packet(db['pk'].encode())
        m = Msg()

        if len(argv) > 2:
            m.sender(Asm.from_to(my_usr_pkt, Asm.user_packet(PublicKey(argv[2].encode(), encoder=B64Encoder).encode())), b'AYY')
            Incoming.put(m)
Client()
