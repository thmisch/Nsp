# Nsc - new simple chat

## Introduction
Nsc is a simple instant messaging platform. It aims to be a simple alternative
to other secure chat platforms like Signal or Matrix, that still provides the
same security while chatting.

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
#3: encrypted message will be sent
   Amsg -> B
```

This layout also ensures that no replay attacks are possible.

### Encrypted database
Nsc stores your messages securely in a database encrypted with your password
(KDFd of course :>)

## current ToDo's
Nsc isn't quite finished yet:
- group chats
- save messages that couldn't be sent to the peers on exit, retry on next launch
- database structures to save msgs
- A usable client (NCurses maybe)
- message types, prefixing each msg with `<type>://`
- voice calling (*may* be possible, probably not though)
