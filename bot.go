package main

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/superp00t/godog/multiparty"
	"github.com/superp00t/godog/xmpp"
)

var (
	c     *xmpp.Client
	name  = "ROBOCOP"
	lobby = "stringy@conference.ikrypto.club"
	me    *multiparty.Me
)

func local(name string) string {
	return strings.Split(name, "/")[1]
}

func send(mesg string) {
	c.SendMessage(lobby, "groupchat", me.SendMessage([]byte(mesg)))
}

func sendf(format string, args ...interface{}) {
	send(fmt.Sprintf(format, args...))
}

func main() {
	me = multiparty.NewMe(name)

	var err error
	c, err = xmpp.Opts{
		WSURL: "wss://ikrypto.club/socket",
		Host:  "ikrypto.club",
		Debug: true,
		Nick:  name,
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

		go func() {
			switch t.(type) {
			case xmpp.Message:
				msg := t.(xmpp.Message)
				switch msg.Type {
				case "groupchat":
					normalName := local(msg.From)
					b, err := me.ReceiveMessage(normalName, msg.Body)
					if err != nil {
						fmt.Println("Error decrypting message:", err)
						c.SendMessage(lobby, "groupchat", me.SendPublicKey(normalName))
					} else {
						if b != nil {
							message := string(b)
							fmt.Printf("<%s>\t%s\n", normalName, message)
							if strings.HasPrefix(message, name+": ") {
								cmd := strings.Split(message, " ")
								switch cmd[1] {
								case "time":
									sendf("The time is %v", time.Now())
								case "help":
									sendf("Commands: \n\ttime\n\thelp")
								case "hello":
									sendf("Hello to you as well, %s!", normalName)
								// case "kick":
								// 	if normalName == "kommy" {
								// 		if len(cmd) == 3 {
								// 			c.Kick(lobby, cmd[2], "It has been ordained")
								// 			sendf("GTFO, %s!", cmd[2])
								// 		} else {
								// 			sendf("No can do, %s.", normalName)
								// 		}
								// 	}
								case ".":
									sendf("%s: .", normalName)
								default:
									sendf("%s is not a valid command. Type %s: help for help.", cmd[1], name)
								}
							}
							// if message == "RIP Harambe" {
							// 	c.SendMessage(lobby, "groupchat", me.SendMessage([]byte("dicks out")))
							// }
						}
					}
				}
			case xmpp.Presence:
				pres := t.(xmpp.Presence)
				loc := local(pres.From)
				if loc == name {
					break
				}

				switch pres.Type {
				case "unavailable":
					fmt.Printf("User %s is now logged out.\n", loc)
					me.DestroyUser(loc)
				default:
					//fmt.Printf("Presence from %s of type %s\n", pres.From, pres.Type)
					c.SendMessage(lobby, "groupchat", me.SendMessage([]byte(fmt.Sprintf("Hello, %s!", loc))))
				}
			}
		}()
	}
}
