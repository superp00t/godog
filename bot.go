package main

import (
	"fmt"
	"log"
	"strings"

	"github.com/superp00t/godog/multiparty"
	"github.com/superp00t/godog/xmpp"
)

func main() {
	name := "harambe"
	lobby := "lobby@conference.ikrypto.club"

	me := multiparty.NewMe(name)

	c, err := xmpp.Opts{
		WSURL: "wss://ikrypto.club/socket",
		Host:  "ikrypto.club",
		Debug: false,
	}.Connect()

	if err != nil {
		log.Fatal(err)
	}

	c.JoinMUC(lobby, name)

	for {
		t, err := c.Recv()
		if err != nil {
			log.Fatal(err)
		}

		switch t.(type) {
		case xmpp.Message:
			msg := t.(xmpp.Message)
			normalName := strings.Split(msg.From, "/")[1]
			b, err := me.ReceiveMessage(normalName, msg.Body)
			if err != nil {
				if err.Error() == "sendPublicKey" {
					c.SendMessage(lobby, "groupchat", me.SendPublicKey(normalName))
				} else {
					fmt.Println("Error decrypting message:", err)
				}
			} else {
				if b != nil {
					message := string(b)
					fmt.Printf("<%s>\t%s\n", normalName, message)
					if message == "RIP Harambe" {
						c.SendMessage(lobby, "groupchat", me.SendMessage([]byte("dicks out")))
					}
				}
			}
		case xmpp.Presence:
			// pres := t.(xmpp.Presence)
			// fmt.Printf("Presence from %s\n", pres.From)
		}
	}
}
