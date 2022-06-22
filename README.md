# Nsc - new simple chat
## Introduction
Nsc is a simple instant messaging platform. It aims to be a simple alternative
to other secure chat platforms like Signal or Matrix, that still provides the
same security while chatting.

## Install
A Linux or unix-like operating system is required. If you have access to such,
run install.py as root to install the Nsc client and server on your system.

```
sudo ./install.py
```

## Features:
### Client-server architecture
This means that you won't have to connect to peers directly while using Nsc,
unlike a peer-to-peer architecture. This design decision means that The server
could log metadata, e.g the frequency of the messages your sending, the sizes 
of the messages, time information etc. This design is pretty usual though and
can be found in lots of other communication systems.

### End-to-end encryption
Each message you send will be encrypted on your device and decrypted on the peers 
side. The server has no way of seeing your message contents.

### Perfect forward secrecy
Nsc achieves perfect forward secrecy by using a different encryption key for each
new message. This is how ***each*** message is sent:

```
#1: key exchange using random exchange keys
   Apk -> B
   A   <- Bpk
#2: each peer derives the secret key used for message encryption
#3: the message can now be sent out securely
   Amsg -> B
```

Replay attacks aren't possible with this layout Nsc uses.
Here is an example to prove that.

If Eve is intercepting the conversation with Alice,

```
Alice <-> Eve <-> Server <-> Bob
```

The only thing Eve can see is either:

- The `PubExKey`s Alice is using in her KEX packets.
- The encrypted message contents Alice is sending out.

1. Replaying a KEX
Why would Eve do that? He doesn't have access to the private part of the 
exchange key, so if a response KEX would come in, he would have no way of
establishing a shared key, that he could use replay the message.

2. Replaying a MSG packet
This option makes as much sense as replaying a kex, because if Eve were to 
just replay it, Bob would have no way of knowing how to decrypt that message,
because after a KEX key was used, it immediately gets deleted from `kex_cache`.

### Encrypted database
Nsc stores your messages securely in a database encrypted with your password
(KDFd of course :>)

### More information
- Nsc provides confidentiality, authentication and integrity
## current ToDo's
Nsc isn't quite finished yet:
- group chats
- A usable client (cli based)
- voice calling (*may* be possible, probably not though since TCP and Nsc's encryption is pretty slow)

## current security issues
Nsc as a whole features great security, but there still are minor issues:
- The client uses its own 'encrypted' database. I've put it in quotes, since
when it's decrypted, the entire database lives unencrypted in memory for the
rest of the programs lifetime. This opens a lot of possibilities for an attacker
to just read the unencrypted data (still very unlikely, would need a python exploit to work).
- If someone sends you a message they *could* crash your running client, so 
when you encounter such report it to <Nsc-ID> please.
(Probably there's still some weird bug in the protocol :o)