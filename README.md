# Nsc - new simple chat
## Introduction
Nsc is a simple instant messaging platform. It aims to be a simple alternative
to other secure chat platforms like Signal or Matrix, that still provides the
same security while chatting.

## Install
A Linux or unix-like operating system is required. If you have access to such,
run install.py as root to install the Nsc client and server on your system.

```
pip install bson xdg pynacl toml
# TODO: sudo ./install.py
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
#1: key exchange using random exchange keys (pk == public exchange key)
   Apk -> B
   A   <- Bpk
#2: each peer derives the secret key used for message encryption & 
    authentication
#3: the message can now be sent out securely
   Amsg -> B
```

Replay attacks aren't possible with this layout.
Here is an example to prove that point.

If Eve is intercepting the conversation with Alice,

```
Alice <-> Eve <-> Server <-> Bob
```

The only thing Eve can see is either:

- The `PubExKey`s Alice is using in her KEX packets.
- The encrypted message contents Alice is sending out.

1. Replaying a KEX
Why would Eve do that? He doesn't have access to the private part of the 
exchange key, so if a response KEX would come in from Bob, he would have no way of
establishing a shared key, that he could use replay the message.

2. Replaying a MSG packet
This option makes as much sense as replaying a KEX, because if Eve were to 
just replay it, Bob would have no way of knowing how to decrypt that message,
because after a MSG packet comes in, the KEX keys used immediately get deleted from `kex_cache`.

### Encrypted database
Nsc stores your messages securely in a database encrypted with your password
(KDFd of course :>)

### More information
- Nsc provides confidentiality, authentication and integrity

## current ToDo's
Nsc isn't quite finished yet:
- group chats
- A usable client (cli based)
- voice calling (*may* be possible, probably not though since TCP and Nsc's encryption are pretty slow)

## current security issues
Nsc as a whole features great security, but there still are minor issues:

- **python implementation only:** The client uses its own 'encrypted' database. I've put it in quotes, since
when it's decrypted, the entire database lives unencrypted in memory for the
rest of the programs lifetime. This opens a lot of possibilities for an attacker
to just read the unencrypted data (still very unlikely, would need a python exploit to work).
- If someone sends you a message they *could* crash your running client, so 
when you encounter such report it to <Nsc-ID> please.
(Probably there's still some weird bug in the protocol :o)

## Comparison to other chat systems
Nsc is very diffrent from traditional chat systems. It uses a client-server
architecture, but doesn't require much resources or much of anything to host the server:
A raspberrypi (8gb) has enough memory to have 60-70 million clients connected 
(if the cpu and/or network can handle that though :D...)

Also some features you expect just *aren't possible* with the Nsc protocol:

- the server can't save messages for an offline recipient, since the actual message can only be
sent out *after* a key exchange, for which *both* need to be online.

To solve this, the client is just trying to resend the messages at a certian interval. This means
that if a user would like to send a message to some other offline peer, they'd have to be connected
all of the time, retrying to send it every few seconds.

This is very different from e.g. email or signal, matrix.
So the best option is to use a device that has very little downtime: your cellphone.

## Implementations
Currently there's only one implementation that's designed for linux desktop
computers. Due to the above described differences, Nsc needs high availability
to function correctly, which usually a PC can't provide 
(people turn them off because they're loud and inefficient).
Which means: it's like encrypted IRC at this point.

In the future I'll implement the protocol in a language like Javascript, or convert sth. to webASM,
that can be used on mobile operating systems like android and IOS to create native apps for them.
I also want to add a web UI that can be used on desktop devices, that communicates via the phone
app, much like WhatsApp Web.
