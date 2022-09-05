# Nsc - new simple chat
Nsc is a new KISS instant messaging platform.

In this repository you'll find documentation of
the [base protocol](doc/protocol.md), [protocol extensions](doc/protocol-extensions.md) and the
server and client reference implementations.

## Why use Nsc over other messengers?
Tired of slow, insecure, privacy infringing and bloated systems?
Tired of hard-to-use systems which aim to fix the aforementioned issues?

Nsc doesn't *aim* to fix these issues, Nsc already fixed them.

## Features:
### Typical Client-server architecture
This means that you **won't** have to connect to peers directly while using Nsc,
unlike a peer-to-peer architecture. This design decision means that a Nsc server
could log metadata, for example the frequency of the messages your sending or 
rough message sizes. This design is pretty usual though and can be found in
lots of other secure communication systems.

### End-to-end encryption
Each message you send will be encrypted on your device and decrypted on the peers 
side. The server has no way of seeing your message contents.

### Perfect forward secrecy
Nsc achieves perfect forward secrecy by using a different encryption key for each
sent message (#1). This is the procedure used for sending messages:

```
#1: key exchange using random, one time exchange keys
   A -(KEX)> B
   B -(KEX)> A
#2: A encrypts their message with the shared secret of A(sk) and B(pk) (their main, unchanging keys).
#3: Now A encrypts the message again, but this time with the shared secret of A(rsk) and B(rpk) (their random, one time keys)
#4: the message can now be sent out securely
   A -(MSG)> B
```

### No replay attacks
Replay attacks aren't possible with the above layout.
Here is an example which proves that.

If Eve is intercepting the conversation with Alice,

```
Alice <-> Eve <-> Server <-> Bob
```

Eve wants to replay (i.e resend) Alices messages. He would do that by
capturing one of Alice's `MSG` packets and then resending them at a later time. 

However: The content of message is encrypted twice (see #2 and #3). #3 is what 
stops Eve, since the recipient Bob doesn't have the random exchange
key (his private part) in memory anymore since it's deleted immidiately after 
recieving a message. Eve's replayed message wouldn't go through to him.

So what Eve would need to do, is to initiate a new cycle on his own, starting
at #1. Eve can't get after step #2 though, since he doesn't have Alice's
private key to establish the shared secret with Bob.

### Encrypted database
Your messages are securely stored on-device in a database which is 
encrypted with your password (which is KDFd ofc. :>).

## License
Nsc, its protocols and documentation are free and opensource, 
being licensed under the GPL 3.