# Godog

![godog](https://img.ikrypto.club/2ENO.png)

This is a general-purpose API for writing programs that interact with Cryptodog.

It can speak two protocols: Phoxy (developed by yours truly) and BOSH-XMPP, which is terrible and slow but still in use by many people. 

The multiparty implementation has been mostly a line-by-line translation from Cryptodog's, with some help from the protocol spec. However, I cannot guarantee that it is a safe one.

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
conn.HandleFunc(phoxy.USERJOIN, func(ev *phoxy.Event) {
    conn.Groupf("Greetings, %s!", ev.Username)
})

// Echo in all caps
conn.HandleFunc(phoxy.GROUPMESSAGE, func(ev *phoxy.Event) {
    conn.GroupMessage(strings.ToUpper(ev.Body))
})

err := conn.Connect()
if err != nil {
    // handle err
}
```