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

class DealWith:
    def __init__(self, obj):
        print("dealing with:", obj)

class BackgroundGet:
    def __init__(self, socket):
        global db
        while True:
            print('Do')
            Incoming.put(Socket(socket).get())

class BackgroundRetry:
    def __init__(self, socket):
        global db
        self.to_do = list()
        while True:
            try:
                obj = BackBurner.get(block=True if not self.to_do else False)
                self.to_do.append(obj)
            except:
                obj = self.to_do[-1]
            print('retrying', obj)
            Socket(socket).put(obj)
            print('getting')
            res = Socket(socket).get()
            print("fin_ getting")
            if res == Err("offline"):
                self.to_do.insert(0, self.to_do.pop())
                time.sleep(2)
            else:
                self.to_do.remove(obj)
                print('ay', res)
                Incoming.put(res)

class Connection:
    def __init__(self):
        global db
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, int())
        self.sock.connect(CON)
        self.server_login(db['sk'])
        # threading.Thread(target=BackgroundRetry, args=(deepcopy(self.sock), )).start()
        threading.Thread(target=BackgroundGet, args=(self.sock,)).start()
        my_usr_pkt = Asm.user_packet(db['pk'].encode())
        while True:
            obj = Incoming.get()
            if not obj['From'] == my_usr_pkt:
                DealWith(obj)
            elif not obj['From'] == obj['To']:
                Socket(self.sock).put(obj)
                res = Socket(self.sock).get()
                if res == Err("offline"):
                    BackBurner.put(obj)
                else:
                    Incoming.put(res)
     
        self.sock.close()

    # login the `key` on the server and prove that you're the owner of it.
    def server_login(self, key):
        # do the key exchange
        public_key = key.public_key.encode()
        Socket(self.sock).put(Asm.user_packet(public_key))
        server_exchange_key = PublicKey(Socket(self.sock).get()['PubKey'])
        
        # encrypt and send the the public key to the server
        box = Box(key, server_exchange_key)
        msg = box.encrypt(public_key)
        Socket(self.sock).put(Asm.msg_packet(msg, dict()))

class Client:
    def __init__(self, pw = 'XXX'):
        global db
        db = Login(pw, argv[1]).db
        threading.Thread(target=Connection).start()
        print(db['pk'].encode(B64Encoder))

        my_usr_pkt = Asm.user_packet(db['pk'].encode())
        if len(argv) > 2:
            kex_packet_to_myself = Asm.kex_packet(
                PrivateKey.generate().public_key.encode(),
                Asm.from_to(my_usr_pkt, Asm.user_packet(PublicKey(argv[2].encode(), encoder=B64Encoder).encode()))
                #Asm.from_to(my_usr_pkt, my_usr_pkt)

            )
            Incoming.put(kex_packet_to_myself)

Client()
