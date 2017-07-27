# Godog

![godog](https://img.ikrypto.club/iGGo.png)

This is a general-purpose API for writing programs that interact with ~~Cryptodog~~ my personal Cryptodog server.. 

The multiparty implementation has been mostly a line-by-line translation from Cryptodog's, with some help from the protocol spec. However, I cannot guarantee that it is a safe one.

The XMPP implementation is not very good. It only connects to WebSocket XMPP servers, and cannot do much. I intend to add more functionality soon.

An example bot is included in this directory.
```
$ go build .
$ ./bot -a [phoxy api key]
```
