# Nsp (New Simple Protocol)
Nsp is an application layer network protocol designed for simplicity, security, and extensibility. It offers forward secrecy and uses the libsodium crypto library for encryption. Nsp supports custom sub-protocols and comes with a reference server and API implementation in Python. It is suitable for a wide range of applications, including messaging and chat, IoT, Home Automation and much more.

## Key Features
* Simple by design
* Forward secrecy
* Highly extensible with sub-protocols
* Uses libsodium for encryption
* Simple reference server and API implementation in Python
* Suitable for messaging and chat applications

## Getting Started
To start using Nsp, have a look at the reference implementation for servers, client-API and explore the available sub-protocols. You can also use Nsp to create your own custom sub-protocols tailored to your specific use case. Nsp's simple design and support for custom sub-protocols make it easy to integrate into your existing applications or build new ones from scratch.

## Security
Nsp prioritizes security and privacy. It uses the libsodium crypto library for encryption and provides forward secrecy to ensure that past communications remain secure even if a user's key is compromised in the future. All data sent using Nsp is end-to-end encrypted.

## Extensibility
Nsp supports custom sub-protocols, allowing you to build new features and capabilities on top of the core protocol. This makes Nsp highly adaptable to different use cases and applications. You can use Nsp to create messaging and chat applications, as well as other networked applications that require a simple, secure, and extensible protocol.

## Applications using Nsp
The following applications are known to use Nsp. If you are developing an application using Nsp, please contribute to this list by submitting a pull request to the README.

* Nsc (https://github.com/thmisch/Nsc): A secure and privacy-focused messaging app built on top of Nsp.

We welcome contributions to this list to showcase the diverse range of applications that can be built using Nsp.

## Deeper Protocol Documentation
For those who want to dive deeper into the details of the Nsp protocol, the following sections provide a more comprehensive documentation of its features and functionalities.

### Message Format
There is only one message type in Nsp, which has the following format:

```
[DEST, CONTENT]
```

* `DEST` is the public key of the sender/recipient.
* `CONTENT` is data that can be anything serializable by Msgpack.

The content can be anything because the protocol is designed to support custom sub-protocols
(anything that Msgpack can serialize, that is).

### Sub-protocol Format
A sub-protocol is just a list (in the main `CONTENT` e.g) that looks like this:

```
[TYPE/ID, CONTENT]
```

* `TYPE/ID` can be an integer or binary value. This ID is used to handle the message correctly
* `CONTENT` can be anything serializable by Msgpack.

### Encryption
Nsp uses the libsodium cryptographic library for encryption, since security is prioritized over speed. All keys, such as the public keys used in the `DEST` field, are generated using the default settings by libsodium.

### Handshake
The handshake between server S and client A is as follows:

1. A & S derive a session_secret, that is used from now on as the 1st encryption layer.

```
A -> S: [random_session_pk]

S -> A: [random_session_pk]
```

2. Next, A gives their pk, and their pk encrypted with the shared secret of them and S.

```
A -> S: [session_secret [Apk, Apk encrypted with Ask & Spk]]
```

If S can decrypt this, it means A is legit since they must have had their secret key.

A & S derive `shared_secret` from Ask & Spk or Ssk & Apk respectively.

`shared_secret` is from now on used as the 2nd encryption layer.

If A can decrypt the next incoming messages from the server, A knows that S is legit too.

### Connection Trace
Here's an example connection trace from a conversation of clients A & B.

```
# A sends KexInitial
A -> B: [shared_secret [ArandomPk]]

# B sends KexReply
B -> A: [shared_secret [BrandomPk]]
    
# A sends the final message now
A -> B: [shared_secret [shared_random_secret [CONTENT]]]
```

* `CONTENT`: some binary data, most likely though some encoded sub-protocol.
* `shared_secret`: different from the one used in the handshake: its the shared secret between A & B.
* `shared_random_secret`: NOTE: MUST NOT be reused, else forward secrecy will be compromised.
