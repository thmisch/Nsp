# common code shared with the server and client
import socket
import threading
import bson
import toml

from pathlib import Path
from os.path import exists
from os import remove, makedirs
from xdg import xdg_data_home

from nacl.encoding import URLSafeBase64Encoder as B64Encoder
from nacl.public import PrivateKey, Box, PublicKey
import nacl.pwhash
import nacl.utils
import pickle
from argparse import ArgumentParser
bson.patch_socket()

# simplify sending and recieving of messages
class Socket:
    def __init__(self, peer):
        self.peer = peer

    def put(self, obj):
        self.peer.sendobj(obj)

    def get(self):
        return self.peer.recvobj()

# build the protocol packets
class Asm:
    def user_packet(pubkey):
        return {
            "Type": "USR",
            "PubKey": pubkey,
        }

    def from_to(from_usr_packet, to_peer_packet):
        return {"From": from_usr_packet, "To": to_peer_packet}

    def kex_packet(exchange_key, from_to):
        return {"Type": "KEX", "PubExKey": exchange_key, **from_to}

    def msg_packet(message, from_to):
        return {"Type": "MSG", "Message": message, **from_to}

def Err(what):
    return {"err": what}

def Ok(what):
    return {"ok": what}

class UIMessages:
    welcome = """
    Welcome to Nsc, the new simple chat.
    To start chatting, please enter your (new) password.
    """
    pass_prompt = "Password: "

# TODO: don't hardcode this
CON = ("87.187.26.105", 32471)

COMMON_PATH = Path(xdg_data_home(), "nsc")
def backend_socket_path(extra):
    return str(Path(COMMON_PATH, 'backend' + extra)).encode()