# Godog

![godog](https://img.ikrypto.club/2ENO.png)

This is a general-purpose API for writing programs that interact with the main Cryptodog XMPP-BOSH server and Phoxy servers. 

The multiparty implementation has been mostly a line-by-line translation from Cryptodog's, with some help from the protocol spec. However, I cannot guarantee that it is a safe one.

The XMPP implementation is not very good. It only connects to WebSocket XMPP servers, and cannot do much. I intend to add more functionality soon.

An example bot is included in this directory.
```
$ go get -u github.com/superp00t/godog
$ $GOPATH/bin/godog -a [phoxy api key]
```

## API usage
### Connection (Standard XMPP Protocol)
```go

opts := phoxy.Opts {
    Type:     phoxy.BOSH,
    Username: "username",
    Chatroom: "lobby",
    Endpoint: "https://crypto.dog/http-bind/",
}

conn, err := phoxy.New(&opts)
if err != nil {
    // handle err
}
```

### Connection (Phoxy WebSocket Protocol)
```go

opts := phoxy.Opts {
    Type:     phoxy.PHOXY,
    Username: "username",
    Chatroom: "lobby",
    Endpoint: "https://ikrypto.club/phoxy/",
}

conn, err := phoxy.New(&opts)
if err != nil {
    // handle err
}
```

### Event handlers

```go
conn.HandleFunc("userJoin", func(ev *phoxy.Event) {
    conn.Groupf("Greetings, %s!", ev.Username)
})

// Echo in all caps
conn.HandleFunc("groupMessage", func(ev *phoxy.Event) {
    conn.GroupMessage(strings.ToUpper(ev.Body))
})

err := conn.Connect()
if err != nil {
    // handle err
}
```