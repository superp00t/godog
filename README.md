# Godog

![godog](https://img.ikrypto.club/2ENO.png)

This is a general-purpose API for writing programs that interact with Cryptodog.

The multiparty implementation has been mostly a line-by-line translation from Cryptodog's, with some help from the protocol spec. However, I cannot guarantee that it is a safe one.
```
$ go get -u github.com/superp00t/godog
$ $GOPATH/bin/godog -a [phoxy api key]
```

## API usage
### Connection (Phoxy WebSocket Protocol) 
```go

import "github.com/superp00t/godog/phoxy"

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

conn.HandleFunc(phoxy.USERQUIT, func(ev *phoxy.Event) {
    conn.Groupf("Auf Wiedersehen, %s!", ev.Username)
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