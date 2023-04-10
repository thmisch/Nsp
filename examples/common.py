from Nsp import *

# NOTICE: This is for easy testing only; Never store raw keys inside your code!!
testing_server_sk = PrivateKey(
    b"\xcc\xb7`\xd4V\x1cvu\rg\xcd\xdd\xbdM\x06\xa3\x9d\xf8\x10\x1e|\x074\x13\xaa$\x1d-\x19\xber\xfd"
)
# testing_server_sk = PrivateKey.generate()
testing_server_pk = testing_server_sk.public_key
testing_server_entity = Entity("::1", 11742, testing_server_pk, testing_server_sk)
