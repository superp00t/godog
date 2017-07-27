package phoxy

import (
	"bytes"
	"crypto/dsa"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"golang.org/x/crypto/otr"
	"golang.org/x/net/websocket"

	"encoding/base64"

	"time"

	"github.com/superp00t/godog/multiparty"
)

type Packet struct {
	Type     string           `json:"type"`
	Chatroom string           `json:"chatroom,omitempty"`
	Nickname string           `json:"nickname,omitempty"`
	Object   *json.RawMessage `json:"object,omitempty"`
}

func (p Packet) Encode() string {
	var b bytes.Buffer
	json.NewEncoder(&b).Encode(p)
	return b.String()
}

type Event struct {
	Username string
	Body     string
}

type HandlerFunc func(*Event)

type PhoxyConn struct {
	Conn *websocket.Conn
	Me   *multiparty.Me

	APIKey   string
	Handlers map[string]*HandlerFunc

	OTRKey *otr.PrivateKey
	Opts   *Opts
	Errc   chan error
}

type MessageObject struct {
	Type string `json:"type,omitempty"`
	Body string `json:"body,omitempty"`
}

type Opts struct {
	Username, Chatroom string
	Endpoint           string

	APIKey          string
	MpOTRPrivateKey string
	OTRPrivateKey   string
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
	pc.Errc = make(chan error)
	pc.Handlers = make(map[string]*HandlerFunc)
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

func (pc *PhoxyConn) Connect() error {
	var err error
	R, S, err := dsa.Sign(rand.Reader, &pc.OTRKey.PrivateKey, []byte("login"))
	if err != nil {
		return err
	}

	r := R.Bytes()
	s := S.Bytes()

	signedURL := pc.BackendURL() + "?k=" + urlEncode(pc.OTRKey.PublicKey.Serialize(nil))
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
			case "user_join":
				pc.CallFunc("userJoin", &Event{
					Username: pkt.Nickname,
				})
				h := json.RawMessage(pc.Me.SendPublicKey(pkt.Nickname))
				go func() {
					for _ = range make([]int, 5) {
						time.Sleep(300 * time.Millisecond)
						pc.Send(Packet{
							Type:     "groupchat",
							Chatroom: pc.Opts.Chatroom,
							Object:   &h,
						})
					}
				}()
			case "groupchat":
				msgb, err := pc.Me.ReceiveMessage(pkt.Nickname, string(*pkt.Object))
				if err != nil {
					continue
				}
				if msgb != nil {
					var msgo2 MessageObject
					json.Unmarshal(msgb, &msgo2)
					pc.CallFunc("groupMessage", &Event{
						Username: pkt.Nickname,
						Body:     msgo2.Body,
					})
				}
			case "chat":

			case "unavailable":
				pc.Me.DestroyUser(pkt.Nickname)
				pc.CallFunc("userQuit", &Event{
					Username: pkt.Nickname,
				})
			case "ping":
				pc.Send(Packet{
					Type: "pong",
				})
			}
		}
	}()

	return <-pc.Errc
}

func (pc *PhoxyConn) CallFunc(typ string, msg *Event) {
	if h := pc.Handlers[typ]; h != nil {
		he := *h
		go he(msg)
	}
}

func (pc *PhoxyConn) Send(p Packet) {
	if err := websocket.Message.Send(pc.Conn, p.Encode()); err != nil {
		pc.Errc <- err
		return
	}
}

func (pc *PhoxyConn) HandleFunc(typ string, h HandlerFunc) {
	pc.Handlers[typ] = &h
}

func (pc *PhoxyConn) GroupMessage(body string) {
	enc := MessageObject{
		Type: "message",
		Body: body,
	}
	dat, _ := json.Marshal(enc)
	msg := pc.Me.SendMessage(dat)
	h := json.RawMessage(msg)
	pc.Send(Packet{
		Type:     "groupchat",
		Chatroom: pc.Opts.Chatroom,
		Object:   &h,
	})
}

func (pc *PhoxyConn) Groupf(body string, args ...interface{}) {
	pc.GroupMessage(fmt.Sprintf(body, args...))
}

func (pc *PhoxyConn) Ban(chat, name string) error {
	if pc.Opts.APIKey == "" {
		return fmt.Errorf("need api key")
	}

	r, err := http.Get(pc.APIURL("/ban/") + name + "/" + chat)
	if err != nil || r.StatusCode == 404 {
		return fmt.Errorf("unauthorized")
	}

	return nil
}

type cleanupReport struct {
	Status int    `json:"status"`
	Error  string `json:"error"`

	NamesCleaned int `json:"names_cleaned"`
}

func (pc *PhoxyConn) Cleanup(chat string, time int64) (int, error) {
	if pc.Opts.APIKey == "" {
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

func (pc *PhoxyConn) Lockdown(chat string) error {
	if pc.Opts.APIKey == "" {
		return fmt.Errorf("need api key")
	}

	r, err := http.Get(pc.APIURL("/lockdown/") + chat)
	if err != nil || r.StatusCode == 404 {
		return fmt.Errorf("unauthorized")
	}

	return nil
}

type authorizedAnswer struct {
	IsAuthorized bool `json:"authorized"`
}

func (pc *PhoxyConn) IsAuthorized(chat, name string) bool {
	if pc.Opts.APIKey == "" {
		return false
	}

	r, err := http.Get(pc.APIURL("/is_authorized/") + name + "/" + chat)
	if err != nil || r.StatusCode != 200 {
		return false
	}

	var a authorizedAnswer
	err = json.NewDecoder(r.Body).Decode(&a)
	if err != nil {
		return false
	}

	return a.IsAuthorized
}

func (pc *PhoxyConn) BackendURL() string {
	str := strings.Replace(pc.Opts.Endpoint, "http", "ws", 1)
	return str + "backend"
}

func (pc *PhoxyConn) APIURL(path string) string {
	return pc.Opts.Endpoint + pc.Opts.APIKey + path
}
