package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/ogier/pflag"
	"github.com/superp00t/godog/phoxy"
)

const HOST = "cryptodog.ikrypto.club"

type Session struct {
	C net.Conn

	Nick string
	UF   *UserFrame

	Rdline *bufio.Reader
	B      *phoxy.PhoxyConn
}

func (s *Session) Wframe(f Frame) {
	s.C.Write(f.Serialize())
}

func (s *Session) SendAuthMsg() {
	fmt.Fprintf(s.C, ":%s 001 %s :Welcome to the Phoxy IRC bridge %s\n", HOST, s.Nick, s.Nick)
	fmt.Fprintf(s.C, ":%s MODE %s :+i\n", s.Nick, s.Nick)
}

func (s *Session) Notice(auth, msg string) {
	fr := &Frame{
		"NOTICE",
		auth,
		":***",
		msg,
	}
	s.C.Write(fr.Serialize())
}

func (s *Session) Authorized() {
	s.SendAuthMsg()

lp:
	for {
		str, err := s.Rdline.ReadString('\n')
		if err != nil {
			break
		}
		cmds := strings.Split(str, " ")
		switch cmds[0] {
		case "PING":
			fmt.Fprintf(s.C, ":%s PONG %s :%s\n", HOST, HOST, HOST)
		case "QUIT":
			break lp
		case "PRIVMSG":
			body := strings.Join(cmds[2:], " ")
			body = body[1 : len(body)-2]
			s.B.GroupMessage(body)
		case "JOIN":
			go func(cmd []string) {
				chatName := cmd[1][1:]

				chatName = strings.TrimRight(chatName, string([]byte{13, 10}))
				log.Println(chatName)
				log.Println([]byte(chatName))
				realName := chatName
				endpoint := "https://ikrypto.club/phoxy/"

				typ := phoxy.PHOXY
				if strings.HasPrefix(chatName, "cd_") {
					realName = strings.TrimLeft(chatName, "cd_")
					typ = phoxy.BOSH
					endpoint = "https://crypto.dog/http-bind/"
				}

				Log(DEBUG, "Requested to join chat \"%s\"", chatName)
				var err error
				s.B, err = phoxy.New(&phoxy.Opts{
					Type:     typ,
					Username: s.Nick,
					Chatroom: realName,
					Endpoint: endpoint,
					APIKey:   "",
				})

				if err != nil {
					s.Notice("AUTH", err.Error())
					return
				}

				fp := hex.EncodeToString(s.B.Me.PublicKey[:])
				s.Notice("AUTH", "Your mpOTR fingerprint is "+fp)

				s.B.HandleFunc(phoxy.USERQUIT, func(ev *phoxy.Event) {
					fmt.Fprintf(s.C, ":%s!~_ QUIT :Quit: leaving\n", ev.Username)
				})

				s.B.HandleFunc(phoxy.USERJOIN, func(ev *phoxy.Event) {
					fmt.Fprintf(s.C, ":%s!~_ JOIN #%s\n", ev.Username, chatName)
				})

				s.B.HandleFunc(phoxy.GROUPMESSAGE, func(ev *phoxy.Event) {
					stre := strings.Split(ev.Body, "\n")
					for _, v := range stre {
						fmt.Fprintf(s.C, ":%s!~_ PRIVMSG #%s :%s\n", ev.Username, chatName, v)
					}
				})

				if err := s.B.Connect(); err != nil {
					s.Notice("AUTH", err.Error())
				}
			}(cmds)
		}

		Log(DEBUG, "Got auth string, %s", str)
	}

	if s.B != nil {
		s.B.Disconnect()
	}
}

func NewSession(c net.Conn) {
	s := &Session{
		C: c,
	}
	s.Notice("AUTH", "Hey")

	s.Rdline = bufio.NewReader(c)
	authFlags := 0

ml:
	for {
		str, err := s.Rdline.ReadString('\n')
		if err != nil {
			break
		}

		// Trim newline
		l := len(str) - 1
		char := str[:l]
		if char == "\n" {
			Log(DEBUG, "Removing newline")
			str = str[:l-1]
		}

		elements := strings.Split(str, " ")
		switch elements[0] {
		case "NICK":
			pNick := elements[1]
			pNick = pNick[:len(pNick)-2]
			s.Nick = pNick
			authFlags++
		case "USER":
			s.UF = DeserializeUserFrame(str)
			authFlags++
		case "QUIT":
			break ml
		default:
			log.Println("Unknown command", elements[0])
		}

		Log(DEBUG, "Got data: %+v", s.UF)

		if authFlags == 2 {
			s.Authorized()
			return
		}
	}
	c.Close()
}

func main() {
	addrptr := pflag.StringP("listen", "l", ":6667", "The IP address to listen on")
	pflag.Parse()
	addr := *addrptr

	l, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}

	for {
		c, err := l.Accept()
		if err != nil {
			continue
		}

		go NewSession(c)
	}
}
