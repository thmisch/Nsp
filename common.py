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
from enum import Enum
bson.patch_socket()

# simplify sending and recieving of messages
class Socket:
    def __init__(self, peer):
        self.peer = peer

    def put(self, obj):
        self.peer.sendobj(obj)

    def get(self):
        return self.peer.recvobj()

# assemble protocol packets
class PACKT:
    USR = 1
    KEX = 2
    MSG = 3

class PACK:
    TYPE = 0
    PK   = 4
    PEK  = 5
    FROM = 6
    TO   = 7
    CONTS = 8

class Asm:
    def usr(pk):
        return {PACK.TYPE: PACKT.USR, PACK.PK: pk}
    
    def from_to(frm, to):
        return {PACK.FROM: frm, PACK.TO: to}
    
    def kex(pek, from_to):
        return {PACK.TYPE: PACKT.KEX, PACK.PEK: pek, **from_to}
    
    def msg(conts, from_to):
        return {PACK.TYPE: PACKT.MSG, PACK.CONTS: conts, **from_to}
CON = ("localhost", 32471)

COMMON_PATH = Path(xdg_data_home(), "nsc")
