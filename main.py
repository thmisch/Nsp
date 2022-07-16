import socket
import ssl
import threading

from common import *
from crypt import *
from tinydb import TinyDB, Query
import readline
from getpass import getpass
from inspect import signature
import signal

context = ssl.create_default_context()
context.load_verify_locations('keys/cert.pem')

BgToSend, BgResult = [Queue()] * 2
db = TinyDB(conf.DB)
db.Q = Query()

kex_cache = list()
class DBOps:
    def __init__(self, usr):
        self.usr = usr

def get_user_entry(username):
    entry = db.search(db.Q['User']['Username'] == username)
    if entry:
        return entry[0]

# assemble all the packet structures for the protocol
class Asm:
    def user_packet(username, pubkey, signature):
        return {
                'Type': 'USR',
                'Username': username,
                'PubKey': pubkey,
                'Signature': signature
                }

    def from_to(from_usr_packet, to_peer_packet):
        return {
                'From': from_usr_packet,
                'To': to_peer_packet
                }

    def kex_packet(exchange_key, from_to):
        return {
                'Type': 'KEX',
                'PubExKey': exchange_key,
                **from_to
                }

    def msg_packet(message, from_to):
        return {
                'Type': 'MSG',
                'Message': message,
                **from_to
                }

class AsmDB:
    def user(user_packet):
        return {
            'User': user_packet
        }

    def message(content, typ):
        return {
            'Message': content,
            'Type': typ,
            'Time': time.time(),
            'Delivered': False
        }

    def base_myself(user_packet, private_key):
        return {
            **AsmDB.user(user_packet),
            'Chats': list(),
            'PEM': private_key
        }

    def base_peer(peer_user_packet):
        return {
            **AsmDB.user(peer_user_packet),
            'Messages': list(),
        }

class Background:
    def __init__(self, kex, s):
        # connect to the server
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        self.sock.connect(conf.ADINFO)
        self.ssock = context.wrap_socket(self.sock, server_hostname=conf.HOST)

        self.m = msg(self.ssock)
        self.kex = kex 
        self.m.send(self.kex.usr)

        if not s:
            self.bg()
        else:
            self.normal()

    def end(self):
        time.sleep(0.2)
        self.ssock.close()
        self.sock.close()

    def normal(self):
        global kex_cache
        while True:
            self.m.send(self.kex.StageOne())
            kex_cache.append(self.kex)
            result = self.m.recieve()
            if result == Message('suc').Ok():
                # kex_cache.append(self.kex)
                print('sent kex -> peer')
                break
            else:
                kex_cache.pop()
                time.sleep(2)
        self.end()

    def bg(self):
        global kex_cache
        while True:
            obj = self.m.recieve()
            if not obj:
                continue
            if obj.get('Type') == 'KEX':
                if not kex_cache:
                    # reciever
                    kex_cache.append(self.kex.SavePeerPubKey(obj))
                    self.m.send(self.kex.toSend)
                else:
                    # sender
                    kex_cache[0].SavePeerPubKey(obj)
                    self.m.send(kex_cache[0].send_msg())

                    # don't clear the list, if the sender is sending a message to itself
                    if kex_cache[0].usr['PubKey'] != kex_cache[0].peer['PubKey']:
                        kex_cache = list()

            elif obj.get('Type') == 'MSG':
                print('decrypted:', kex_cache[0].get_msg(obj))
                kex_cache = list()

class Const:
    WelcomeMessage = """
    Welcome to Nsc, the simplest secure chat platform.

    To begin chatting, log in or create your new account.
    """

class Cmd:
    def __init__(self, usr_packet):
        self.usr_packet = usr_packet

        self.prompt = None
        self.peer = None
        self.next_msg_type = 'TEXT'

        self.cmds = [
            self.gen(
                'cd',
                """
                cd <Chat-Name>

                Change 'directory' into the specified Chat-Name.
                In your chat directory, no other commands except:
                `..` or `type` will work.
                """,
                self.cd
            ),
            self.gen(
                '..',
                """
                ..

                Change your directory back to your home (~),
                e.g. get out of the current chat.
                """,
                self.dot_dot
            ),
            self.gen(
                'help',
                """
                help

                Get the help page returned (this).
                """,
                self.help
            ),
            self.gen(
                'type',
                """
                type <Msg-Type>

                Set the type of the next message you're going to send.
                If you don't do that, the message type 'TEXT' will be selected.
                For a file use 'FILE', for just binary data use 'BIN'.

                These different types will determine how the peers client will
                handle your message.
                
                If you specify 'get' as argument, the current type
                will be printed out
                """,
                self.msg_type
            ),
            self.gen(
                'info',
                """
                info

                Display your account information, and some stats.
                """,
                self.info
            ),
            self.gen(
                'ls',
                """
                ls

                See all the people you chatted with on your current account.
                """,
                self.ls
            )
        ]
    def gen(self, name, desc, fn):
        return {
            'Name': name,
            'Desc': desc,
            'Exec': fn
        }
    
    def cd(self, args):
        def setprompt(what):
            self.prompt = '<{}>'.format(what)
        user = args[0]
        try:
            self.peer = UserPacket(user).decode()
            setprompt(self.peer['Username'])
        except: 
            if user in self.get_peers():
                for real_user in self.get_peers(full=True):
                    if real_user['Username'] == user:
                        self.peer = real_user
                        setprompt(user)
                        return
            print("An error occured while parsing NscID.")
            self.dot_dot()

    def dot_dot(self):
        self.prompt = None
        self.peer = None
 
    def help(self):
        for cmd in self.cmds:
            print(cmd['Name'])
            print(cmd['Desc'])

    def msg_type(self, args):
        mtype = args[0].upper()
        correct = ['TEXT', 'BIN', 'FILE']
        if mtype == 'GET':
            print(self.next_msg_type)
        elif not mtype in correct:
            print(
                """
                Wrong type specified, correct values can be:
                {}
                """.format(correct)
            )
        else:
            self.next_msg_type = mtype
    
    def info(self):
        users = self.get_peers()
        print(
            """
            Your name is: {}
            Your NscID is: {}
            You chatted with {} people:
            {}
            """.format(
                self.usr_packet['Username'],
                UserPacket(self.usr_packet).encode(),
                len(users),
                users
                )
        )

    def ls(self):
        print(self.get_peers())

    def get_propmt(self):
        v = '~'
        if self.prompt:
            v = self.prompt
        return v + ' '
    
    def get_peers(self, full=False):
        all_usernames = list()
        entry = get_user_entry(self.usr_packet['Username'])
        for user in entry['Chats']:
            v = user['User']['Username']
            if full:
                v = user['User']
            all_usernames.append(v)
        return all_usernames

    def exec_by_name(self, args):
        if not args:
            return
        for cmd in self.cmds:
            if args[0] == cmd['Name']:
                if self.peer and cmd['Name'] != '..':
                    return True
                # right amount of arguments
                x = len(signature(cmd['Exec']).parameters)
                if x > 0:
                    if len(args)-1 >= x:
                        cmd['Exec'](args[1:])
                    else:
                        print('Not enough arguments specified.')

                else:
                    cmd['Exec']()
                return
        if self.peer:
            return True

class KEX:
    def __init__(self, crypto, usr, peer=None, message=None):
        # cryto instance provided by CryptoInit
        self.crypto = crypto
        
        # both user packets
        self.usr = usr
        self.peer = peer
        
        # message to send to the peer (if specified)
        self.message = message

        self.peer_pub_key = None
        
        # clients' own exchange keys
        self.my_key = None

        sf = False
        if peer and message:
            sf = True

        self.newsig()
        threading.Thread(target=Background, daemon=True, args=(self,sf)).start()
    
    # create the keypair for use in the handshake (one time use)
    def gen_key(self):
        priv = ec.generate_private_key(
            ec.SECP256R1()
        )
        pub = priv.public_key()
        return {
                'Private': priv,
                'Public': PubSwap.obj_to_pem(pub)
                }

    def kxSend(self, PubExKey):
        self.newsig()
        return Asm.kex_packet(
            PubExKey,
            Asm.from_to(
                self.usr,
                self.peer
            )
        )

    def StageOne(self):
        self.my_key = self.gen_key()
        return self.kxSend(self.my_key['Public'])

    def SavePeerPubKey(self, packet):
        if not self.my_key:
            self.my_key = self.gen_key()
        self.peer = packet['From']
        self.peer_pub_key = packet['PubExKey']
        self.toSend = self.kxSend(self.my_key['Public'])
        return self

    def make(self, pub_key):
        raw_key = self.my_key['Private'].exchange(ec.ECDH(), PubSwap.pem_to_obj(pub_key))
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=None,
        ).derive(raw_key)
        return Fernet(urlsafe_b64encode(derived_key))

    def send_msg(self, msg=None):
        return Asm.msg_packet(
            self.make(self.peer_pub_key).encrypt(self.message.encode()),
            Asm.from_to(
                self.usr,
                self.peer
            )
        )

    def get_msg(self, obj):
        if obj['From']['Signature'] == self.peer['Signature']:
            print('INVALID MESSAGE')
        obj['Message'] = self.make(self.peer_pub_key).decrypt(obj['Message']).decode()
        return obj

    def newsig(self):
        self.usr['Signature'] = Crypto.sign(self.crypto.private_key, self.usr['Username'])

class Main:
    def __init__(self):
        # exit on ^C
        signal.signal(signal.SIGINT, self.sig_handler)
        
        self.login()
        self.cmd = Cmd(self.usr_packet)
        while True:
            self.loop()
    
    def sig_handler(self, signum, sigframe):
        print('\n\n\tCu next time.\n\n')
        exit(0)

    def loop(self):
        user_input = input(self.cmd.get_propmt())
        user_arr = user_input.split()
        cmd_result = self.cmd.exec_by_name(user_arr)

        # client wants to send peer a message
        if cmd_result:
            my_db_entry = get_user_entry(self.usr_packet['Username'])
            
            # client doesn't know peer yet
            if not self.cmd.peer in self.cmd.get_peers(full=True):
                new_peer_entry = AsmDB.base_peer(self.cmd.peer)
                my_db_entry['Chats'].append(new_peer_entry)

            # encrypt the message and save it at the right location
            for i, chat in enumerate(my_db_entry['Chats']):
                if chat['User'] == self.cmd.peer:
                    my_db_entry['Chats'][i]['Messages'].append(
                        AsmDB.message(user_input, self.cmd.next_msg_type)
                    )
                    break

            db.update(
                my_db_entry,
                db.Q.User['Username'] == self.usr_packet['Username']
            )
            # wait for the last kex to finish (to avoid errors)
            while kex_cache:
                pass
            # start a new thread dedicated for sending the message
            KEX(self.crypto, self.usr_packet, peer=self.cmd.peer, message=user_input)
    
    def login(self):
        print(Const.WelcomeMessage)

        # find and login the user from the database
        db_elems = db.all()
        #if len(db_elems) == 1:
        #    username = db_elems[0]['User']['Username']
        #else:
        username = input('Username: ')

        password = getpass()

        user_entry = get_user_entry(username)
        if not user_entry:
            print('Creating new user `{}`.'.format(username))
            self.crypto = CryptoInit(password)
            self.usr_packet = Asm.user_packet(
                            username,
                            PubSwap.obj_to_pem(self.crypto.public_key),
                            # signature of the username
                            Crypto.sign(self.crypto.private_key, username)
                        )
            entry = AsmDB.base_myself(
                        self.usr_packet,
                        self.crypto.pem
                )
            
            db.insert(entry)
        else:
            self.usr_packet = user_entry['User']
            self.crypto = CryptoInit(password, pem=user_entry['PEM'])
        
        KEX(self.crypto, self.usr_packet)

if __name__ == '__main__':
    Main()
