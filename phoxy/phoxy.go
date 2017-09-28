package phoxy

import (
	"bytes"
	"crypto/dsa"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"golang.org/x/crypto/otr"
	"golang.org/x/net/websocket"

	"encoding/base64"
	mrand "math/rand"

	"time"

	"github.com/superp00t/godog/multiparty"
	"github.com/superp00t/godog/xmpp/bosh"
)

type ConnType int

const (
	PHOXY ConnType = iota
	BOSH
)

type HandlerField int

const (
	USERJOIN HandlerField = iota
	USERQUIT
	GROUPMESSAGE
	PRIVATEMESSAGE
	VERIFY
)

type OTRMessage struct {
	Body string `json:"body"`
}

type Packet struct {
	Type     string           `json:"type"`
	Chatroom string           `json:"chatroom,omitempty"`
	Nickname string           `json:"nickname,omitempty"`
	Object   *json.RawMessage `json:"object,omitempty"`
	ID       string           `jsoh:"id,omitempty"`
	Verified bool             `json:"verified"`
}

func (p Packet) Encode() string {
	var b bytes.Buffer
	json.NewEncoder(&b).Encode(p)
	return b.String()
}

type Event struct {
	Type     HandlerField `json:"type" xorm:"'type'"`
	Username string       `json:"username" xorm:"'username'"`
	Body     string       `json:"body" xorm:"longtext 'body'"`
	At       int64        `json:"at" xorm:"'at'"`
	Callback chan bool    `json:"-" xorm:"-"`
}

type HandlerFunc func(*Event)

type PhoxyConn struct {
	Conn *websocket.Conn
	BC   *bosh.Conn
	Me   *multiparty.Me

	APIKey   string
	Handlers map[HandlerField]*HandlerFunc

	OTRKey *otr.PrivateKey
	Opts   *Opts
	Errc   chan error

	Closed bool
	PM     map[string]*otr.Conversation

	interceptor func(*Event)
}

type MessageObject struct {
	Type string `json:"type,omitempty"`
	Body string `json:"body,omitempty"`
}

type Opts struct {
	Type               ConnType
	Username, Chatroom string
	Endpoint           string

	APIKey          string
	MpOTRPrivateKey string
	OTRPrivateKey   string

	SpamTesting bool
	BeFilter    bool
}

func urlEncode(inp []byte) string {
	input := base64.StdEncoding.EncodeToString(inp)

	input = strings.Replace(input, "+", ".", -1)
	input = strings.Replace(input, "=", "-", -1)
	input = strings.Replace(input, "/", "_", -1)

	return input
}

func New(o *Opts) (*PhoxyConn, error) {
	pc := new(PhoxyConn)
	pc.Errc = make(chan error, 10)
	pc.PM = make(map[string]*otr.Conversation)
	pc.Handlers = make(map[HandlerField]*HandlerFunc)
	ok := new(otr.PrivateKey)
	if o.OTRPrivateKey == "" {
		ok.Generate(rand.Reader)
	} else {
		data, err := base64.StdEncoding.DecodeString(o.OTRPrivateKey)
		if err != nil {
			return nil, err
		}

		_, okay := ok.Parse(data)
		if !okay {
			return nil, fmt.Errorf("can't parse data")
		}
	}

	pc.OTRKey = ok

	pc.Opts = o
	pc.APIKey = o.APIKey
	var err error
	pc.Me, err = multiparty.NewMe(o.Username, o.MpOTRPrivateKey)
	if err != nil {
		return nil, err
	}

	return pc, nil
}

func (pc *PhoxyConn) Intercept(f func(*Event)) {
	pc.interceptor = f
}

func (pc *PhoxyConn) SendPublicKey(nick string) {
	str := pc.Me.SendPublicKey(nick)
	go func() {
		time.Sleep(300 * time.Millisecond)
		if pc.Opts.Type == BOSH {
			if pc.BC != nil {
				pc.BC.SendGroupMessage(str)
			}
		}

		if pc.Opts.Type == PHOXY {
			h := json.RawMessage(str)
			pc.Send(Packet{
				Type:     "groupchat",
				Chatroom: pc.Opts.Chatroom,
				Object:   &h,
			})
		}
	}()
}
func (pc *PhoxyConn) Connect() error {
	if pc.Opts.Type == PHOXY {
		var err error
		R, S, err := dsa.Sign(rand.Reader, &pc.OTRKey.PrivateKey, []byte("login"))
		if err != nil {
			return err
		}

		r := R.Bytes()
		s := S.Bytes()

		signedURL := pc.BackendURL() + "?k=" + urlEncode(pc.OTRKey.PublicKey.Serialize(nil))
		if pc.Opts.SpamTesting {
			signedURL = signedURL + "&fake_ip=" + fakeIP()
		}

		signedURL = signedURL + "&r=" + urlEncode(r)
		signedURL = signedURL + "&s=" + urlEncode(s)

		if pc.Opts.APIKey != "" {
			signedURL = signedURL + "&api_key=" + pc.Opts.APIKey
		}

		pc.Conn, err = websocket.Dial(signedURL, "", "http://localhost/")
		if err != nil {
			return err
		}

		pc.Send(Packet{
			Type:     "join_chat",
			Chatroom: pc.Opts.Chatroom,
			Nickname: pc.Opts.Username,
			Verified: pc.Opts.BeFilter,
		})

		go func() {
			for {
				var msg string
				if err := websocket.Message.Receive(pc.Conn, &msg); err != nil {
					pc.Errc <- err
					return
				}

				var pkt Packet
				err = json.Unmarshal([]byte(msg), &pkt)
				if err != nil {
					pc.Errc <- err
					return
				}

				switch pkt.Type {
				case "verify_message":
					msgb, err := pc.Me.ReceiveMessage(pkt.Nickname, string(*pkt.Object))
					if err != nil {
						continue
					}
					if msgb != nil {
						var msgo2 MessageObject
						json.Unmarshal(msgb, &msgo2)
						cb := make(chan bool)
						go func(cb chan bool, id string, msgg MessageObject, usr string) {
							v := <-cb
							log.Println("Sending verified response", v, msgg.Type)
							pc.Send(Packet{
								Type:     "verify_response",
								ID:       id,
								Verified: v,
							})
							if v == true && msgg.Type == "message" {
								pc.CallFunc(GROUPMESSAGE, &Event{
									Username: usr,
									Body:     msgg.Body,
								})
							}
						}(cb, pkt.ID, msgo2, pkt.Nickname)
						pc.CallFunc(VERIFY, &Event{
							Username: pkt.Nickname,
							Body:     msgo2.Body,
							Callback: cb,
						})
					}
				case "user_join":
					pc.CallFunc(USERJOIN, &Event{
						Username: pkt.Nickname,
					})
					pc.SendPublicKey(pkt.Nickname)
				case "groupchat":
					msgb, err := pc.Me.ReceiveMessage(pkt.Nickname, string(*pkt.Object))
					if err != nil {
						continue
					}
					if msgb != nil {
						log.Println("Received message from", pkt.Nickname)
						var msgo2 MessageObject
						json.Unmarshal(msgb, &msgo2)
						pc.CallFunc(GROUPMESSAGE, &Event{
							Username: pkt.Nickname,
							Body:     msgo2.Body,
						})
					}
				case "chat":
					var cnv *otr.Conversation
					if cnv = pc.PM[pkt.Nickname]; cnv == nil {
						cnv = &otr.Conversation{
							PrivateKey:   pc.OTRKey,
							Rand:         rand.Reader,
							FragmentSize: 0,
						}
						pc.PM[pkt.Nickname] = cnv
					}
					var msg OTRMessage
					json.Unmarshal([]byte(*pkt.Object), &msg)
					out, _, _, _, err := cnv.Receive([]byte(msg.Body))
					if err == nil {
						pc.CallFunc(PRIVATEMESSAGE, &Event{
							Username: pkt.Nickname,
							Body:     string(out),
						})
					}
				case "unavailable":
					pc.Me.DestroyUser(pkt.Nickname)
					pc.CallFunc(USERQUIT, &Event{
						Username: pkt.Nickname,
					})
				case "ping":
					pc.Send(Packet{
						Type: "pong",
					})
				}
			}
		}()
	}

	if pc.Opts.Type == BOSH {
		go func() {
			c := &bosh.Config{
				BOSHEndpoint:     pc.Opts.Endpoint,
				Domain:           "crypto.dog",
				ConferenceDomain: "conference.crypto.dog",
				Lobby:            pc.Opts.Chatroom,
				HumanName:        pc.Opts.Username,
			}

			err := bosh.NewConversation(c, func(c *bosh.Conn, ev *bosh.XMPPEvent) {
				pc.BC = c
				switch ev.Type {
				case "UserJoin":
					pc.CallFunc(USERJOIN, &Event{
						Username: ev.Username,
					})
					pc.SendPublicKey(ev.Username)
				case "UserQuit":
					pc.CallFunc(USERQUIT, &Event{
						Username: ev.Username,
					})
					pc.Me.DestroyUser(ev.Username)
				case "GroupchatMessageReceived":
					if ev.Username == pc.Opts.Username {
						return
					}
					msgb, err := pc.Me.ReceiveMessage(ev.Username, ev.Message)
					if err != nil {
						pc.SendPublicKey(ev.Username)
						return
					}
					if msgb != nil {
						pc.CallFunc(GROUPMESSAGE, &Event{
							Username: ev.Username,
							Body:     string(msgb),
						})
					}
				}
			})
			if err != nil {
				pc.Errc <- err
			}
		}()
	}

	return <-pc.Errc
}

func (pc *PhoxyConn) CallFunc(typ HandlerField, msg *Event) {
	msg.Type = typ
	msg.At = time.Now().UnixNano()
	if pc.interceptor != nil {
		pc.interceptor(msg)
	}

	if h := pc.Handlers[typ]; h != nil {
		he := *h

		go he(msg)
	}
}

func (pc *PhoxyConn) Send(p Packet) {
	if pc.Conn == nil {
		return
	}
	if err := websocket.Message.Send(pc.Conn, p.Encode()); err != nil {
		pc.Errc <- err
		return
	}
}

func (pc *PhoxyConn) HandleFunc(typ HandlerField, h HandlerFunc) {
	pc.Handlers[typ] = &h
}

func (pc *PhoxyConn) GroupMessage(body string) {
	if pc.Opts.Type == BOSH {
		if pc.BC != nil {
			pc.BC.SendGroupMessage(pc.Me.SendMessage([]byte(body)))
		}
		return
	}

	enc := MessageObject{
		Type: "message",
		Body: body,
	}
	dat, _ := json.Marshal(enc)
	msg := pc.Me.SendMessage(dat)

	if pc.Opts.Type == PHOXY {
		h := json.RawMessage(msg)
		pc.Send(Packet{
			Type:     "groupchat",
			Chatroom: pc.Opts.Chatroom,
			Object:   &h,
		})
	}
}

func (pc *PhoxyConn) Groupf(body string, args ...interface{}) {
	pc.GroupMessage(fmt.Sprintf(body, args...))
}

func (pc *PhoxyConn) Ban(chat, name string) error {
	if !pc.AmIAuthorized() {
		return fmt.Errorf("Unauthorized")
	}

	r, err := http.Get(pc.APIURL("/ban/") + name + "/" + chat)
	if err != nil || r.StatusCode == 404 {
		return fmt.Errorf("unauthorized")
	}

	return nil
}

func (pc *PhoxyConn) Chmod(chat, name, level string) error {
	if !pc.AmIAuthorized() {
		return fmt.Errorf("Unauthorized")
	}

	r, err := http.Get(pc.APIURL("/chmod/") + name + "/" + chat + "/" + level)
	if err != nil || r.StatusCode == 404 {
		return fmt.Errorf("unauthorized")
	}

	return nil
}

type User struct {
	IPAddress string `json:"ip_address"`
}

type Chatroom struct {
	Members map[string]*User `json:"members"`
}

func (pc *PhoxyConn) GetChatrooms() (map[string]*Chatroom, error) {
	if !pc.AmIAuthorized() {
		return nil, fmt.Errorf("Unauthorized")
	}

	r, err := http.Get(pc.APIURL("/chatrooms"))
	if err != nil || r.StatusCode == 404 {
		return nil, fmt.Errorf("unauthorized")
	}

	rsp := make(map[string]*Chatroom)
	json.NewDecoder(r.Body).Decode(&rsp)
	return rsp, nil
}

func (pc *PhoxyConn) ClearJail() error {
	if !pc.AmIAuthorized() {
		return fmt.Errorf("Unauthorized")
	}

	r, err := http.Get(pc.APIURL("/clear_jail"))
	if err != nil || r.StatusCode == 404 {
		return fmt.Errorf("unauthorized")
	}

	return nil
}

func (pc *PhoxyConn) Interrupt(chat, name string) error {
	rsp, err := pc.GetChatrooms()
	if err != nil {
		return err
	}

	if c := rsp[chat]; c != nil {
		if m := c.Members[name]; m != nil {
			r, err := http.Get(pc.APIURL("/interrupt/" + m.IPAddress))
			if err != nil || r.StatusCode == 404 {
				return fmt.Errorf("unauthorized")
			}
		}
	}

	return fmt.Errorf("unauthorized")
}

type cleanupReport struct {
	Status int    `json:"status"`
	Error  string `json:"error"`

	NamesCleaned int `json:"names_cleaned"`
}

func (pc *PhoxyConn) Cleanup(chat string, time int64) (int, error) {
	if !pc.AmIAuthorized() {
		return 0, fmt.Errorf("need api key")
	}

	r, err := http.Get(pc.APIURL("/cleanup/") + chat + "/" + fmt.Sprintf("%d", time))
	if err != nil || r.StatusCode == 404 {
		return 0, fmt.Errorf("unauthorized")
	}

	var cr cleanupReport
	json.NewDecoder(r.Body).Decode(&cr)

	return cr.NamesCleaned, nil
}

func (pc *PhoxyConn) Lockdown(chat, level string) error {
	if !pc.AmIAuthorized() {
		return fmt.Errorf("need api key")
	}

	r, err := http.Get(pc.APIURL("/lockdown/") + chat + "/" + level)
	if err != nil || r.StatusCode == 404 {
		return fmt.Errorf("unauthorized")
	}

	return nil
}

type authorizedAnswer struct {
	AccessLevel int64 `json:"access_level"`
}

func (pc *PhoxyConn) AmIAuthorized() bool {
	if pc.Opts.Type == BOSH {
		return false
	}

	if pc.Opts.APIKey == "" {
		return false
	}

	return true
}

func (pc *PhoxyConn) IsAuthorized(chat, name string) bool {
	if !pc.AmIAuthorized() {
		return false
	}

	return pc.AccessLevel(chat, name) > 4
}

func (pc *PhoxyConn) AccessLevel(chat, name string) int64 {
	if !pc.AmIAuthorized() {
		return -1
	}

	r, err := http.Get(pc.APIURL("/access_control/") + name + "/" + chat)
	if err != nil || r.StatusCode != 200 {
		return -1
	}

	var a authorizedAnswer
	err = json.NewDecoder(r.Body).Decode(&a)
	if err != nil {
		return -1
	}

	return a.AccessLevel
}

func (pc *PhoxyConn) BackendURL() string {
	str := strings.Replace(pc.Opts.Endpoint, "http", "ws", 1)
	return str + "backend"
}

func (pc *PhoxyConn) APIURL(path string) string {
	return pc.Opts.Endpoint + pc.Opts.APIKey + path
}

func fakeIP() string {
	oct := make([]string, 4)
	for v := 0; v < 4; v++ {
		oct[v] = fmt.Sprintf("%d", mrand.Intn(255))
	}

	fk := strings.Join(oct, ".")
	return fk
}

func (pc *PhoxyConn) Disconnect() {
	pc.Closed = true
	if pc.Opts.Type == PHOXY {
		pc.Conn.Close()
	}

	if pc.Opts.Type == BOSH {
		if pc.BC != nil {
			pc.BC.Disconnect()
		}
	}
}
