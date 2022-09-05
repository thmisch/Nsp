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

#class Asm:
#    
#    def user_packet(pubkey):
#        return {"Type": "USR", "PubKey": pubkey}####
#
#    def from_to(from_usr_packet, to_peer_packet):
#        return {"From": from_usr_packet, "To": to_peer_packet}#
#
#    def kex_packet(exchange_key, from_to):
#        return {"Type": "KEX", "PubExKey": exchange_key, **from_to}##
#
#    def msg_packet(message, from_to):
#        return {"Type": "MSG", "Message": message, **from_to}

# build the protocol packets
PACK = Enum("PACK", "TYPE USR KEX MSG PK PEK FROM TO CONTS")
class Asm:
    def usr(pk):
        return {PACK.TYPE: PACK.USR, PACK.PK: pk}
    
    def from_to(from, to):
        return {PACK.FROM: from, PACK.TO: to}
    
    def kex(pek, from_to):
        return {PACK.TYPE: PACK.KEX, PACK.PEK: pek, **from_to}
    
    def msg(conts, from_to):
        return {PACK.TYPE: PACK.MSG, PACK.CONTS: conts, **from_to}

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
CON = ("themisch.strangled.net", 32471)

COMMON_PATH = Path(xdg_data_home(), "nsc")
def backend_socket_path(extra):
    return str(Path(COMMON_PATH, 'backend' + extra)).encode()
