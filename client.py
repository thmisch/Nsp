from database import *
from common import *
from queue import Queue
import time
import curses, curses.textpad

# exchange data between threads
Incoming = Queue()
kex_cache = list()
offline_kexs = list()

# create and/or decrypt the database
class Login:
    def __init__(self, pw):
        self.pw = pw
        self.path = Path(xdg_data_home(), "nsc")

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
        return self

    def sender(self, from_to, message):
        self.kex_packet = Asm.kex_packet(self.exchange_key.public_key.encode(), from_to)
        self.kex_packet["init"] = True
        self.message = message
        self.sent = True
        return self

class Connection:
    def __init__(self):
        # create and start the background listening threads
        self.threads = [
            threading.Thread(target=self.BgGet),   
            threading.Thread(target=self.BgPut)
        ]
        for th in self.threads:
            th.start()
    
    # create the required database structures if not already existing
    # and save any incoming messsage at the right place.
    def asmDB(self, name, msg, who):
        global db
        if not name in db:
            db[name] = {
                'viewable_name': None,
                'chat': list()
            }
        db[name]['chat'].append(
            {
                'time': time.time(),
                'who': who,
                'msg': msg
            }
        )

    def BgGet(self):
        global db, kex_cache
        sock = self.server_login(db["sk"])

        while True:
            res = Socket(sock).get()
            typ = type(res) == dict
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
                    m = Msg().recipient(res)
                    kex_cache.append({res["From"]["PubKey"]: m})
                    Socket(sock).put(m.kex_packet)
                    print('replied kex')

            elif typ and res.get("Type") == "MSG":
                for i, kex in enumerate(kex_cache):
                    m = kex.get(res["From"]["PubKey"])
                    if m:
                        del kex_cache[i]
                        try:
                            msg = m.box.decrypt(res["Message"])
                            # TODO: MSG INTERRUPT, maybe MSGGOT queue.put
                            print('got msg', msg)

                            frm = res["From"]["PubKey"]
                            self.asmDB(frm, msg, frm)
                        except Exception as e:
                            # kex_cache = list()
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
                # save the sent out message
                self.asmDB(k, obj.message, db['my_usr_pkt']['PubKey'])
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
                    # be nice to the central processing unit
                    time.sleep(.1)
            else:
                k, entry = get_entry_from(obj)
                if get_another_offline(k):
                    offline_kexs.append(obj)
                else:
                    try_obj(obj, sock)

            # only try to re-send messages to offline peers half of the time
            what = not what

    # login the public key `key` on the server and prove that you're the owner 
    # of it (i.e have the corresponding private key).
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

class WinShare:
    def __init__(self):
        pass
win_share = WinShare()

class ContactsWindow:
    def __init__(self):
        self.selected = int()
        pass
    
    def header(self):
        pass
    def subheading(self):
        pass

    # find all contact entrys
    def create_contact_list(self):
        self.contacts = list()
        for contact in db.keys():
            if type(contact) == bytes:
                self.contacts.append(contact)

    def action(self, key):
        self.create_contact_list()
        self.key = key
        if len(self.contacts):
            if key in (curses.KEY_DOWN,):
                self.selected += 1 
            elif key in (curses.KEY_UP,):
                self.selected -= 1
            self.selected %= len(self.contacts)

    def render(self):
        s = "Your Contacts"
        self.curses.addstr(1,1, s.center(self.x+1))

        for i, contact in enumerate(self.contacts):
            name = B64Encoder().encode(contact).decode()
            vname = db[contact]['viewable_name']
            if vname:
                name = vname
            self.curses.addstr(2+i, 1, name)
            self.curses.move(self.selected+2+i, 1)

class ChatsWindow:
    def __init__(self):
        pass
    def action(self, key):
        self.key = key
        pass
    def render(self):
        self.curses.addstr(1,0,  ' ')
        # self.curses.move(1,1)
        self.curses.addstr('' if not type(self.key) == str else self.key)
        pass

class TextEditWindow:
    def __init__(self):
        pass
    def action(self, key):
        pass
    def render(self):
        self.curses.move(1,1)
        pass

class Client:
    def __init__(self, pw="XXX"):
        global db
        db = Login(pw).db
        threading.Thread(target=Connection).start()
        myu = db['my_usr_pkt']
        m = Msg().sender(
            Asm.from_to(
            myu,
            myu
            ),
            b"M ess age"
            )
        Incoming.put(m)
        db.sync()
        curses.wrapper(self.main)

    def create_windows(self, update = False):
        self.y, self.x = self.scr.getmaxyx()
        raw_wins = [
            curses.newwin(self.y, int(.33 * self.x), 0, 0),
            curses.newwin(int(.77 * self.y), int(.67 * self.x), 0, int(.33 * self.x)),
            curses.newwin(int(.23 * self.y) + 1, int(.67 * self.x), int(.77 * self.y), int(.33 * self.x))
        ]
        for w in raw_wins:
            w.keypad(True)
        if not update:
            self.windows = [
                ContactsWindow(),
                ChatsWindow(),
                TextEditWindow()
            ]
        for win, curs in zip(self.windows, raw_wins):
            win.curses = curs

    def main(self, scr):
        self.scr = scr
        
        self.cur_contact = None
        self.text_buffer = dict()
        self.cur_win = int()

        self.create_windows()
        self.render()

        self.run = True
        while self.run:
            self.loop()

    def render(self, k = None):
        # render all windows, but the current window at last
        for w in ( self.windows[:self.cur_win]
            + self.windows[self.cur_win+1:]
            + [self.windows[self.cur_win]]
            ):
            w.y, w.x = w.curses.getmaxyx()
            w.curses.erase()
            w.action(k)
            w.render()
            w.curses.border()
            w.curses.refresh()

    def loop(self):
        k = self.windows[self.cur_win].curses.get_wch()

        if k == curses.KEY_RESIZE:
            self.create_windows(update=True)
        elif k == '\t':
            self.cur_win += 1
            self.cur_win %= len(self.windows)
        elif k == 'Q':
            exit()
        self.render(k)

if __name__ == "__main__":
    Client()
