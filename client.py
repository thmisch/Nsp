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
from collections import deque

Incoming, BackBurner = Queue(), Queue()

kex_cache = list()
offline_kexs = list()
kex_lock = threading.Lock()

# Convert nonces around, probably certificates will be used instead
class Nonce:
    def get(obj):
        if type(obj) == bytes:
            obj = Nonce.decode(obj)
        elif type(obj) == int:
            obj = Nonce.encode(obj)
        return obj

    def decode(obj):
        return int.from_bytes(obj, byteorder="big")

    def encode(obj):
        return obj.to_bytes(Box.NONCE_SIZE, byteorder="big")


# create and/or decrypt the database
class Login:
    def __init__(self, pw, path):
        self.pw = pw
        self.path = Path(xdg_data_home(), "nsc" + path)

        self.salt_path = str(Path(self.path, "salt"))
        self.db_path = str(Path(self.path, "db"))

        if not exists(self.path):
            makedirs(self.path)
            if not exists(self.salt_path):
                open(self.salt_path, "a").close()
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
            memlimit=nacl.pwhash.scrypt.MEMLIMIT_INTERACTIVE,
        )
        self.db = PersistentDict(self.db_path, key)

    def create_new_creds(self):
        salt = nacl.utils.random(nacl.pwhash.scrypt.SALTBYTES)
        self.open_db(salt)

        # generate a new key, save it in the encrypted database
        sk = PrivateKey.generate()
        self.db["sk"] = sk
        self.db["pk"] = sk.public_key

        self.db["used_nonces"] = list()

        # save the salt
        with open(self.salt_path, "wb") as f:
            f.write(salt)
        self.db.sync()

    def load_creds(self):
        with open(self.salt_path, "rb") as f:
            salt = f.read()
            self.open_db(salt)


class Msg:
    def __init__(self):
        self.exchange_key = PrivateKey.generate()

    def recipient(self, senders_kex):
        self.kex_packet = Asm.kex_packet(
            self.exchange_key.public_key.encode(),
            Asm.from_to(senders_kex["To"], senders_kex["From"]),
        )
        self.box = Box(self.exchange_key, PublicKey(senders_kex["PubExKey"]))
        self.sent = False

    def sender(self, from_to, message):
        self.kex_packet = Asm.kex_packet(self.exchange_key.public_key.encode(), from_to)
        self.kex_packet["init"] = True
        self.message = message
        self.sent = True


class Connection:
    def __init__(self):
        threading.Thread(target=self.BgGet).start()
        threading.Thread(target=self.BgPut).start()

    def BgGet(self):
        global db, kex_cache, kex_lock
        sock = self.server_login(db["sk"])

        while True:
            res = Socket(sock).get()
            typ = type(res) == dict
            #print('TYPE',typ)
            #print('RES', res)
            sent = False
            if typ and res.get("Type") == "KEX":
                print('got kex')

                for i, kex in enumerate(kex_cache):
                    r = next(iter(kex))
                    m = kex[r]
                    if r == res["From"]["PubKey"] and m.sent:
                        del kex_cache[i]

                        print("sending message")
                        box = Box(m.exchange_key, PublicKey(res["PubExKey"]))
                        msg = box.encrypt(m.message)
                        Socket(sock).put(
                            Asm.msg_packet(msg, Asm.from_to(res["To"], res["From"]))
                        )
                        
                        sent = True
                        break

                if not sent:
                    # reply with another kex
                    m = Msg()
                    m.recipient(res)
                    kex_cache.append({res["From"]["PubKey"]: m})
                    Socket(sock).put(m.kex_packet)
                    print('replied kex')

            elif typ and res.get("Type") == "MSG":
                # asm db structures
                # kex_lock.acquire()
                for i, kex in enumerate(kex_cache):
                    m = kex.get(res["From"]["PubKey"])
                    if m:
                        del kex_cache[i]
                        # kex_lock.release()
                        # kex_ev
                        try:
                            msg = m.box.decrypt(res["Message"])
                            print('got msg', msg)
                        except Exception as e:
                            #self.find_remove({res["From"]["PubKey"]: m})
                            kex_cache = list()
                            print(e)
                            print('cleaned up kex cache')
                        break
            print(kex_cache)

    # send and relay messages in a optimized way.
    def BgPut(self):
        def get_entry_from(obj):
            k = obj.kex_packet["To"]["PubKey"]
            entry = {k: obj}
            return k, entry

        # return the first offline message thats intended to be sent to `name`
        def get_another_offline(name):
            global offline_kexs
            for m in offline_kexs:
                if name == m.kex_packet["To"]["PubKey"]:
                    return m

        # try to send a KEX packet to the peer 
        def try_obj(obj, sock, value = False):
            global offline_kexs, kex_cache
            k, entry = get_entry_from(obj)

            kex_cache.append(entry)
            Socket(sock).put(obj.kex_packet)
            
            x = Socket(sock).get()
            if x == Err("offline"):
                kex_cache.remove(entry)
                if not obj in offline_kexs:
                    offline_kexs.append(obj)
            else:
                if obj in offline_kexs:
                    offline_kexs.remove(obj)
                    another = get_another_offline(k)
                    if another:
                        try_obj(another, sock)

        # only return the first message for each offline peer
        # this is done to retain the order there were in.
        def group_kexes():
            global offline_kexs
            l = list()

            for m in offline_kexs:
                l.append(m.kex_packet["To"]["PubKey"])
            l = set(l)
            res = list()
            for why in l:
                for m in offline_kexs:
                    if why == m.kex_packet["To"]["PubKey"]:
                        res.append(m)
                        break
            return res

        global db, offline_kexs
        sock = self.server_login(db["sk"])
        what = False
        while True:
            if what == False:
                try:
                    obj = Incoming.get(block=False)
                except Exception as e:
                    what = True
            if what == True:
                if not offline_kexs:
                    obj = Incoming.get()
                    what = False

            if what == True:
                for m in group_kexes():
                    try_obj(m, sock, value = True)
                    time.sleep(0.1)
            else:
                k, entry = get_entry_from(obj)
                if get_another_offline(k):
                    offline_kexs.append(obj)
                else:
                    try_obj(obj, sock)

            what = not what

    # login the `key` on the server and prove that you're the owner of it.
    def server_login(self, key):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, int())
        sock.connect(CON)

        # do the key exchange
        public_key = key.public_key.encode()
        Socket(sock).put(Asm.user_packet(public_key))
        server_exchange_key = PublicKey(Socket(sock).get()["PubKey"])

        # encrypt and send the the public key to the server
        box = Box(key, server_exchange_key)
        msg = box.encrypt(public_key)
        Socket(sock).put(Asm.msg_packet(msg, dict()))
        return sock


class Client:
    def __init__(self, pw="XXX"):
        global db
        db = Login(pw, argv[1]).db
        threading.Thread(target=Connection).start()
        print(db["pk"].encode(B64Encoder))

        my_usr_pkt = Asm.user_packet(db["pk"].encode())

        if len(argv) > 2:
            i = 0
            for x in range(100):
            #while True:
                #if 1 < 2:
                #if not kex_cache:
                    m = Msg()
                    m.sender(
                        Asm.from_to(
                            my_usr_pkt,
                            Asm.user_packet(
                                PublicKey(argv[2].encode(), encoder=B64Encoder).encode()
                            ),
                        ),
                        b"Ay" + str(i).encode(),
                    )
                    print('on msg', i)
                    Incoming.put(m)
                    i += 1
            print('done')


Client()
