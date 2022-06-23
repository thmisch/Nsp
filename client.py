from database import *
from common import *
from getpass import getpass
from queue import Queue
import time
import socketserver
from signal import signal, SIGINT

BackendIn = Queue()
BackendOut = Queue()
ErrorEvent = threading.Event()
Stop = threading.Event()

# create and/or decrypt the database
class Database:
    def __init__(self, pw):
        self.pw = pw
        self.path = COMMON_PATH

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
        self.db["my_usr_pkt"] = Asm.user_packet(sk.public_key.encode())
        self.db["offline_kexs"] = list()
        self.db["bs"] = nacl.utils.random(SecretBox.KEY_SIZE)

        # save the salt
        with open(self.salt_path, "wb") as f:
            f.write(salt)
        self.db.sync()

    def load_creds(self):
        with open(self.salt_path, "rb") as f:
            salt = f.read()
            self.open_db(salt)

# store the information required for a key exchange in a convenient way.
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
        return self

    def sender(self, from_to, message):
        self.kex_packet = Asm.kex_packet(self.exchange_key.public_key.encode(), from_to)
        self.kex_packet["init"] = True
        self.message = message
        self.sent = True
        return self

class BackendUnixGet(socketserver.StreamRequestHandler):
    def handle(self):
        global BackendIn, ErrorEvent
        sock = Socket(self.request)
        while True:
            try:
                self.data = sock.get()
                self.data = pickle.loads(SecretBox(SESSION_KEY).decrypt(self.data['None']))
                BackendIn.put(self.data)

            except Exception as e:
                print("error at UnixGet:", e)
                ErrorEvent.set()
                break

class BackendUnixSend(socketserver.StreamRequestHandler):
    def handle(self):
        global BackendOut, ErrorEvent
        sock = Socket(self.request)
        while True:
            try:
                self.rdata = BackendOut.get()
                self.data = {None: SecretBox(SESSION_KEY).encrypt(pickle.dumps(self.rdata))}
                print("sent data back to peer")
                sock.put(self.data)
            except Exception as e:
                BackendOut.put(self.rdata)
                print("error at UnixSend:", e)
                ErrorEvent.set()
                break

class Backend:
    def __init__(self, pw):
        # exchange data between threads
        self.kex_cache = list()
        self.db = Database(pw).db

        # the encryption key used with the client and backend
        global SESSION_KEY
        SESSION_KEY = self.db['bs'] 
        
        # threading.Thread(target=self.ErrorListen, daemon=True).start()
        self.start_unixes()

        # create and start the background listening threads
        threading.Thread(target=self.BgGet, daemon=True).start()
        threading.Thread(target=self.BgPut, daemon=True).start()
        print("Backend running.")
        self.ErrorListen()

    def start_unixes(self):
        print("starting threads")
        servers = [BackendUnixGet, BackendUnixSend]
        self.threads = list()
        for s, w in zip(servers, ['P', 'L']):
            self.threads.append(
                threading.Thread(target=self.server, args=(s, w)) #daemon=True)
            )
        for t in self.threads:
            t.start()

    # try to catch errors from the unix servers, and restart them to hopefully
    # fix the issue.
    def ErrorListen(self):
        global ErrorEvent
        while True:
            ErrorEvent.wait()
            ErrorEvent.clear()
            self.kex_cache = list()
            self.start_unixes()
            print("restarting unix servers.")
        return

    # start the backend server with the provided class `what`
    def server(self, what, location):
        path = backend_socket_path(location)
        if exists(path):
            remove(path)
        with socketserver.UnixStreamServer(path, what) as server:
            print('bg conn thread started sucessfully')
            server.handle_request()

    # login the public key `key` on the server and prove that you're the owner 
    # of it (i.e. have the corresponding private key).
    def server_login(self):
        key = self.db['sk']
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

    # create the required database structures if not already existing
    # and save any incoming messsage at the right place.
    def asm_db(self, name, msg, who):
        if not name in self.db:
            self.db[name] = {
                'viewable_name': None,
                'chat': list()
            }
        self.db[name]['chat'].append(
            {
                'time': time.time(),
                'who': who,
                'msg': msg
            }
        )
        self.db.sync()
        return {name: self.db[name]}

    def BgGet(self):
        global BackendOut
        sock = self.server_login()

        while True:
            res = Socket(sock).get()
            typ = type(res) == dict
            sender = False
            if typ and res.get("Type") == "KEX":
                print('got kex')

                for i, kex in enumerate(self.kex_cache):
                    r = next(iter(kex))
                    m = kex[r]
                    if r == res["From"]["PubKey"] and m.sent:
                        del self.kex_cache[i]

                        print("sending message")
                        box = Box(m.exchange_key, PublicKey(res["PubExKey"]))
                        msg = box.encrypt(bson.dumps(m.message))
                        Socket(sock).put(
                            Asm.msg_packet(msg, Asm.from_to(res["To"], res["From"]))
                        )
                        
                        sender = True
                        break
                # You're recieving a KEX, so reply with a new KEX to get the MSG.
                if not sender:
                    if res["From"] == res["To"]:
                        print("won't send another kex to yourself, duh.")
                        break
                    # reply with another kex
                    m = Msg().recipient(res)
                    self.kex_cache.append({res["From"]["PubKey"]: m})
                    Socket(sock).put(m.kex_packet)
                    print('replied kex')

            elif typ and res.get("Type") == "MSG":
                for i, kex in enumerate(self.kex_cache):
                    m = kex.get(res["From"]["PubKey"])
                    if m:
                        del self.kex_cache[i]
                        try:
                            msg = bson.loads(m.box.decrypt(res["Message"]))
                            print('got msg', msg)

                            frm = res["From"]["PubKey"]
                            BackendOut.put(self.asm_db(frm, msg, frm))
                            print('puttet msg out')
                        except Exception as e:
                            print(e)
                            # self.kex_cache = list()
                            # print('cleaned up kex cache')
                        finally:
                            break
            print(self.kex_cache)

    # send and relay messages in an optimized way.
    def BgPut(self):
        global BackendIn
        def get_entry_from(obj):
            k = obj.kex_packet["To"]["PubKey"]
            entry = {k: obj}
            return k, entry

        # return the first offline message thats intended to be sent to `name`
        def get_another_offline(name):
            for m in self.db['offline_kexs']:
                if name == m.kex_packet["To"]["PubKey"]:
                    return m

        # try to send a KEX packet to the peer 
        def try_obj(obj, sock):
            k, entry = get_entry_from(obj)

            self.kex_cache.append(entry)
            Socket(sock).put(obj.kex_packet)
            
            x = Socket(sock).get()
            if x == Err("offline"):
                self.kex_cache.remove(entry)
                if not obj in self.db['offline_kexs']:
                    self.db['offline_kexs'].append(obj)
            else:
                # save the sent out message
                BackendOut.put(self.asm_db(k, obj.message, self.db['my_usr_pkt']['PubKey']))
                print('puttet msg out')
                if obj in self.db['offline_kexs']:
                    self.db['offline_kexs'].remove(obj)
                    another = get_another_offline(k)
                    if another:
                        try_obj(another, sock)

        # only return the first message for each offline peer
        # this is done to retain the order there were in.
        def group_kexes():
            l = list()

            for m in self.db['offline_kexs']:
                l.append(m.kex_packet["To"]["PubKey"])
            l = set(l)
            res = list()
            for why in l:
                for m in self.db['offline_kexs']:
                    if why == m.kex_packet["To"]["PubKey"]:
                        res.append(m)
                        break
            return res

        sock = self.server_login()

        # what serves as a switch, to allow for offline kexs to be sent out
        # half of the time
        what = False
        while True:
            if what == False:
                try:
                    obj = BackendIn.get(block=False)
                    print("got obj to work on")
                except Exception as e:
                    what = True
            if what == True:
                if not self.db['offline_kexs']:
                    print("got obj to work on")
                    obj = BackendIn.get()
                    what = False
            if what == True:
                for m in group_kexes():
                    try_obj(m, sock)
                    # be nice to the central processing unit
                    time.sleep(.1)
            else:
                k, entry = get_entry_from(obj)
                if get_another_offline(k):
                    self.db['offline_kexs'].append(obj)
                else:
                    try_obj(obj, sock)

            # only try to re-send messages to offline peers half of the time
            what = not what

# set or get the type of a message to send
class MsgType:
    def __init__(self, message):
        self.msg = message

    def set(self, type):
        return {type: self.msg}

    def get(self):
        return next(iter(self.msg))

class Contact:
    def __init__(self, name=None):
        self.addrs = [name]
        self.names = [B64Encoder.encode(addr) if addr else None for addr in self.addrs]

class Client:
    def __init__(self):
        signal(SIGINT, self.exit_handler)

        print(UIMessages.welcome)
        #pw = getpass(UIMessages.pass_prompt)
        pw = 'XYZ'

        self.db = Database(pw).db
        self.backend_box = SecretBox(self.db['bs'])
        self.backend_in = Queue()
        self.mup = self.db["my_usr_pkt"]

        parser = ArgumentParser()
        parser.add_argument('--daemon', action='store_true')
        args = parser.parse_args()

        # the backend thread we have to launch or connect to.
        be_thread = threading.Thread(target=Backend, args=(pw,))

        paths = any([exists(backend_socket_path(p)) for p in ('L', 'P')])

        def start_threads():
            for sock, fn in zip([self.start_backend_conn(p) for p in ('L', 'P')],
                (self.listen_backend, self.put_backend)):
                threading.Thread(target=fn, args=(sock,), daemon=True).start()

        if args.daemon:
            be_thread.start()
        else:
            if not paths:
                be_thread.start()
            start_threads()

            self.run = True
            self.contact = Contact()
            while self.run:
                self.loop()

    def exit_handler(self, sig, frame):
        print("\n\nCu next time. ^w^")

        # cleanup unused unix sockets
        for p in [backend_socket_path(p) for p in ('L', 'P')]:
            if exists(p):
                remove(p)
        exit()

    # return the time difference in string form
    def t_diff(self, ct):
        def asm(val, name):
            mult = False if round(val) == 1 else True
            if not mult:
                name = name[:-1]
            return f"{val} {name} ago."

        diff = int(time.time()) - int(ct)
        if diff < 60:
            return asm(diff, 'seconds')
        elif diff < 3600:
            return asm(round(diff/60), 'minutes')
        elif diff >= 3600 and diff < 3600*24:
            return asm(round(diff/3600), 'hours')
        elif diff >= 3600*24:
            return asm(round(diff/(3600*24)), 'days')

    def displ_msg(self, msg, alias):
        who = B64Encoder.encode(msg['who']) if not alias else alias
        time = self.t_diff(msg['time'])
        #print(msg)
        m = msg['msg'].get('utf-8')

        print(f"\n{time} by {who}:\n{m}\n")

    def shell(self):
        pass

    def loop(self):
        inp = input(str(self.contact.names) + '> ')
        if not inp:
            return
        if len(inp) > 2 and inp[:2] == 'cd':
            self.contact = Contact(B64Encoder.decode(inp[3:]))
        elif len(inp) == 2 and inp == '..':
            self.contact = Contact()
        elif len(inp) == 4 and inp == 'info':
            print(B64Encoder.encode(self.mup['PubKey']))
        else:
            for addr in self.contact.addrs:
                if addr:
                    print("ADDR", addr)
                    m = Msg().sender(
                        Asm.from_to(
                        self.mup,
                        Asm.user_packet(addr)
                        ),
                        MsgType(inp).set("utf-8")
                        )
                    self.backend_in.put(m)

    def listen_backend(self, s):
        while True:
            res = s.get()
            if not res:
                print("err happened at listen_backend")
                break
            res = pickle.loads(self.backend_box.decrypt(res['None']))
            # TODO: save the contact entry
            #self.db[res]
            #print('got from backend: ', dis)
            print(self.displ_msg(res[next(iter(res))]['chat'][-1], None))

    def put_backend(self, s):
        while True:
            obj = self.backend_in.get()
            s.put({None: self.backend_box.encrypt(pickle.dumps(obj))})

    # try to establish a connection to the locally running `Backend`
    def start_backend_conn(self, what):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        for _ in range(2):
            try:
                s.connect(backend_socket_path(what))
                return Socket(s)
            except:
                print("trying to re-connect. ")
                time.sleep(0.1)

if __name__ == "__main__":
    Client()
