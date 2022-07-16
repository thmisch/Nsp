# Nsc - new simple chat
This is Nsc, a simple instant chat platform. It is designed to be the simplest
secure chat system.

## Features
with Nsc you can:
- Enjoy private chatting sessions.
- Enjoy using a great cli interface.
- Host your own Nsc server.
- Send text messages, pictures, audios.
(or any bytes, the protocol doesn't care)
- Send to group chats.

## Install
The install process is different depending on which client/server
you want to use. However the packages that you **always** need are:

```
cryptography
tinydb
msgpack
```

### Server
The connection between the server and client is made using TLS. You
need to create a new certificate for each server you host.

To start the server, just launch it. Or write a systemd service for it.
Oh, and maybe you should change the IP address in the `conf` class in common.py
and in `keys/san.cnf` to the one you want. After you've done that, create a new certificate with the
`keys/create_cert.sh` script.

### Client
At first I wanted to create a GUI app that could be both used on android and desktop.
This changed when I actually tried to build a simple ui and I realized: U can't make it
look nice! 

So that's why the client is commandline only now. (I will happily accept your pull request for a GUI though :D)

## How it's all done
Nsc uses cryptographic features to secure the chat between its users.
Also Nsc minimizes bandwith by using msgpack for the protocol, and compressing
each request with zlib.

1. User Information:
Each user has an username and an EC keypair. The keypair is needed to 
verify you're chatting with the right person. The EC keypair is also used to 
encrypt/decrypt the previously stored messages in the database.

2. Key exchange:
Before each new message, the client will create a random keypair. The public
key will be sent to the recipent. When they recieve it, they will sent you their
public key. Now both clients can get *the same* encryption/decryption key
to encrypt or decrypt the next message.

3. Encryption:
To encrypt the message, Fernet is used with the key from the last key exchange.

4. Storage:
The server **doesn't store anything in a database**, as it doesn't need to. Nsc's client
does all the real work and needs a database to save messages and other things. For that `tinydb` is used, as it
is the simplest and most effective database for text only storage (images and audio are encoded in byte strings).


## ToDo
- find a database that can be used for use with multiple threads
- better general error handling (e.g. in the protocol threads)
- A better protocol (thats more private and tested)
- A real UI (either TUI or GUI)
- ...

## Is it really *that* secure?
Yes!, it is... in theory. As described above, Nsc uses all the neccessery things to create a
private communication with 2 clients: 
- Key exchange (before *each message*),
- username verification,
- message encryption and verification using Fernet. With Fernet the messages can't be modified in transit, as it uses HMACs.
The problem is that the protocol is new and not well tested: there are still *a lot* of **errors and things that could go wrong**. Just be aware of that while using Nsc.

## License
This is software is licensed under the ISC License.
