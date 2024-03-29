#!/usr/bin/env python3
from Nsp import *
from common import *

import time

my_sk = PrivateKey.generate()
other_sk = PrivateKey(b"\xc9\x1c4a-;\xbf`\x87n#+\x87\xa6V\xef\xeaNKtCx\x81N{\xf3\xf8+\xba\xe4\xe2!")
my_pk = my_sk.public_key

myself = Entity(testing_server_entity.ip, testing_server_entity.port, pk=my_pk, sk=my_sk)
other = Entity(
    testing_server_entity.ip,
    testing_server_entity.port,
    pk=other_sk.public_key,
    sk=other_sk,
)

from sys import argv

# We are sender
if len(argv) > 1 and argv[1] == "-s":
    api = Nsp(myself, testing_server_entity)

    # TODO: if you try to send like 100_000 messages, the server, sockets, or something
    # seems to crash / fill up a buffer, halting the client, sender or server
    for i in range(10):
        api.send(to=other.pk, message=f"HIYA, TESTING! {i}".encode())
        time.sleep(0.001)

# We are reciever
else:
    api = Nsp(other, testing_server_entity)
    # incoming is a Queue(); in that queue we got a Message() object (Nsp.py explains everything.)
    while True:
        print(api.incoming.get().conts)
