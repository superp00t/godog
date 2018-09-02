package phoxy

import (
	"bytes"
	"crypto/dsa"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"

	"golang.org/x/crypto/otr"
	"golang.org/x/net/websocket"

	"encoding/base64"
	mrand "math/rand"

	"time"

	"github.com/superp00t/godog/multiparty"
	"github.com/superp00t/godog/xmpp"
)

type ConnType int

const (
	PHOXY ConnType = iota
	BOSH
	WS
)

type HandlerField int

const (
	USERJOIN HandlerField = iota
	USERQUIT
	GROUPMESSAGE
	PRIVATEMESSAGE
	VERIFY
	AUTHSUCCESS
	AUTHFAIL
	JOINED
	USERCONNECT
	COMPOSING
	PAUSED
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
	WS   *xmpp.Client
	Me   *multiparty.Me

	APIKey   string
	Handlers map[HandlerField]*HandlerFunc

	OTRKey *otr.PrivateKey
	Opts   *Opts
	Errc   chan error

	AlreadyJoined map[string]bool

	Closed         bool
	PM             map[string]*otr.Conversation
	PML            *sync.Mutex
	Start          time.Time
	init, recvinit bool
	interceptor    func(*Event)

	allIsWell    bool
	asLock       *sync.Mutex
	userJoinSent map[string]bool
}

type MessageObject struct {
	Type  string `json:"type,omitempty"`
	Body  string `json:"body,omitempty"`
	Value string `json:"value,omitempty"`
}

type Opts struct {
	Type               ConnType
	Username, Chatroom string
	Endpoint           string

	Proxy           string
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
	pc.PML = new(sync.Mutex)
	pc.asLock = new(sync.Mutex)
	pc.Handlers = make(map[HandlerField]*HandlerFunc)
	pc.AlreadyJoined = make(map[string]bool)
	pc.userJoinSent = make(map[string]bool)
	pc.Start = time.Now()
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

	pc.Me.MessageSender(func(b []byte) {
		pc.SendRawGroupMessage(string(b))
	})

	return pc, nil
}

func (pc *PhoxyConn) Intercept(f func(*Event)) {
	pc.interceptor = f
}

func (pc *PhoxyConn) SendColor(color string) {
	if pc.Opts.Type == PHOXY {
		msgo := MessageObject{
			Type:  "change_color",
			Value: color,
		}
		dat, _ := json.Marshal(msgo)
		enc := pc.Me.SendMessage(dat)
		h := json.RawMessage(string(enc))
		pc.Send(Packet{
			Type:     "groupchat",
			Chatroom: pc.Opts.Chatroom,
			Object:   &h,
		})
	}
}

func (pc *PhoxyConn) SendPublicKey(nick string) {
	pc.Me.TransmitPublicKey(nick)
}

func (pc *PhoxyConn) SendRawPrivateMessage(to string, body string) {
	if pc.Opts.Type == PHOXY {
		obj := MessageObject{
			Type: "chat",
			Body: body,
		}

		dat, _ := json.Marshal(obj)
		obje := json.RawMessage(dat)
		pc.Send(Packet{
			Type:     "chat",
			Chatroom: pc.Opts.Chatroom,
			Nickname: to,
			Object:   &obje,
		})
		return
	}

	if pc.Opts.Type == WS && pc.WS != nil {
		pc.WS.SendMessage(pc.Opts.Chatroom+"@conference.crypto.dog/"+to, "chat", body)
	}
}

func (pc *PhoxyConn) SendPrivateMessage(to string, body string, errct int) {
	if errct > 3 {
		return
	}
	pc.PML.Lock()
	c := pc.PM[to]
	pc.PML.Unlock()
	if c == nil {
		go func() {
			time.Sleep(500 * time.Millisecond)
			pc.SendPrivateMessage(to, body, errct+1)
		}()
		return
	}

	d, _ := c.Send([]byte(body))

	for _, v := range d {
		pc.SendRawPrivateMessage(to, string(v))
	}
}

func (pc *PhoxyConn) SendChallenge(to string, question string, answer string) {
	pc.PML.Lock()
	c := pc.PM[to]
	pc.PML.Unlock()
	if c == nil {
		pc.SendRawPrivateMessage(to, "?OTRv2?")
		return
	}

	bmpf := pc.Me.FP(to)
	answer = pc.prepareAnswer(answer, true, bmpf)
	d, err := c.Authenticate(question, []byte(answer))
	if err != nil {
		log.Println(err)
	}
	for _, v := range d {
		pc.SendRawPrivateMessage(to, string(v))
	}
}

func (pc *PhoxyConn) OTRFingerprint(user string) string {
	errs := 0
	for {
		if errs > 5 {
			return ""
		}
		pc.PML.Lock()
		c := pc.PM[user]
		if c == nil {
			errs++
			pc.PML.Unlock()
			time.Sleep(300 * time.Millisecond)
			continue
		}
		pc.PML.Unlock()
		if c == nil {
			return ""
		}
		return strings.ToUpper(hex.EncodeToString(c.TheirPublicKey.Fingerprint()))
	}
}

func (pc *PhoxyConn) prepareAnswer(answer string, ask bool, buddyMpFingerprint string) string {
	first := ""
	second := ""
	answer = strings.ToLower(answer)
	for _, v := range []rune(".,'\";?!") {
		answer = strings.Replace(answer, string(v), "", -1)
	}
	mee := pc.Me.FP("")

	if buddyMpFingerprint != "" {
		if ask {
			first = mee
		} else {
			first = buddyMpFingerprint
		}

		if ask {
			second = buddyMpFingerprint
		} else {
			second = mee
		}

		answer += ";" + first + ";" + second
	}

	return answer
}

func (pc *PhoxyConn) HandleOTRMessage(from string, body string) {
	var cnv *otr.Conversation
	pc.PML.Lock()
	if cnv = pc.PM[from]; cnv == nil {
		cnv = new(otr.Conversation)
		cnv.PrivateKey = pc.OTRKey
		cnv.Rand = rand.Reader
		cnv.FragmentSize = 0
		pc.PM[from] = cnv
	}
	pc.PML.Unlock()

	out, _, chg, toSend, err := cnv.Receive([]byte(body))

	if chg == otr.SMPComplete {
		pc.CallFunc(AUTHSUCCESS, &Event{
			Username: from,
		})
	} else if chg == otr.SMPFailed {
		pc.CallFunc(AUTHFAIL, &Event{
			Username: from,
		})
	}

	if toSend != nil {
		for _, v := range toSend {
			pc.SendRawPrivateMessage(from, string(v))
		}
	}

	if err == nil {
		if out != nil {
			pc.CallFunc(PRIVATEMESSAGE, &Event{
				Username: from,
				Body:     string(out),
			})
		}
	}
}

func (pc *PhoxyConn) Fingerprint(u string) string {
	s, _ := pc.Me.FingerprintUser(u)
	return s
}

func (pc *PhoxyConn) waitUntilAuth(u string, cb func()) {
	go func() {
		for {
			kws := pc.Me.KeyWasSent(u)
			if pc.Me.FP(u) != "" && kws {
				cb()
				return
			} else {
				time.Sleep(500 * time.Millisecond)
			}
		}
	}()
}

func (pc *PhoxyConn) Connect() error {
	if pc.Opts.Type == WS {
		conference := "crypto.dog"
		c, err := xmpp.Opts{
			WSURL: pc.Opts.Endpoint,
			Host:  conference,
			Debug: false,
			Proxy: pc.Opts.Proxy,
		}.Connect()
		if err != nil {
			return err
		}

		c.JoinMUC(pc.Opts.Chatroom+"@conference."+conference, pc.Opts.Username)
		sent := make(map[string]bool)
		go func() {
			for {
				pc.WS = c
				i, err := c.Recv()
				if err != nil {
					if (err.Error() == "That nickname is already in use by another occupant" || err.Error() == "Only occupants are allowed to send messages to the conference") == false {
						pc.Errc <- err
					}
				}

				switch i.(type) {
				case xmpp.Presence:
					pres := i.(xmpp.Presence)
					chatname := strings.Split(pres.From, "/")[1]
					if pres.Type == "unavailable" {
						pc.PML.Lock()
						pc.PM[pres.From] = nil
						pc.PML.Unlock()
						pc.Me.DestroyUser(chatname)
						pc.CallFunc(USERQUIT, &Event{
							Username: chatname,
						})
						sent[chatname] = false
					} else {
						if sent[chatname] == false {
							sent[chatname] = true
							pc.CallFunc(USERCONNECT, &Event{
								Username: chatname,
							})
						}
					}
				case xmpp.Message:
					msg := i.(xmpp.Message)
					chatname := strings.Split(msg.From, "/")[1]
					if msg.Type == "chat" {
						pc.HandleOTRMessage(chatname, msg.Body)
					} else {
						if msg.X.Composing != nil {
							pc.CallFunc(COMPOSING, &Event{
								Username: chatname,
							})
						}

						if msg.X.Paused != nil {
							pc.CallFunc(PAUSED, &Event{
								Username: chatname,
							})
						}

						decrypted, err := pc.Me.ReceiveMessage(chatname, msg.Body)
						if err != nil {
							continue
						}
						if len(decrypted) != 0 {
							pc.CallFunc(GROUPMESSAGE, &Event{
								Username: chatname,
								Body:     string(decrypted),
							})
						}
					}
				}
			}
		}()
	}

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
				case "unavailable":
					pc.CallFunc(USERQUIT, &Event{
						Username: pkt.Nickname,
					})
					pc.PML.Lock()
					pc.PM[pkt.Nickname] = nil
					pc.PML.Unlock()
				case "user_join":
					pc.CallFunc(USERCONNECT, &Event{
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
					var msgo2 MessageObject
					json.Unmarshal([]byte(*pkt.Object), &msgo2)
					pc.HandleOTRMessage(pkt.Nickname, msgo2.Body)
				case "ping":
					pc.Send(Packet{
						Type: "pong",
					})
				}
			}
		}()
	}

	return <-pc.Errc
}

func (pc *PhoxyConn) Close() {
	if pc.Opts.Type == WS {
		pc.WS.Disconnect()
	}
}

func (pc *PhoxyConn) SendComposing() {
	if pc.Opts.Type == WS {
		pc.WS.SendComposing(pc.Opts.Chatroom+"@conference.crypto.dog", "groupchat")
	}
}

func (pc *PhoxyConn) SendPaused() {
	if pc.Opts.Type == WS {
		pc.WS.SendPaused(pc.Opts.Chatroom+"@conference.crypto.dog", "groupchat")
	}
}

func (pc *PhoxyConn) CallFunc(typ HandlerField, msg *Event) {
	if msg.Username == pc.Opts.Username {
		return
	}
	pc.asLock.Lock()
	as := pc.userJoinSent[msg.Username]
	pc.asLock.Unlock()

	if typ == USERCONNECT {
		if pc.allIsWell && as == false {
			pc.userJoinSent[msg.Username] = true
			pc.waitUntilAuth(msg.Username, func() {
				pc.CallFunc(USERJOIN, &Event{
					Username: msg.Username,
				})
			})
		}

		if pc.init == false {
			pc.init = true
			go func() {
				pc.SendPublicKey("")
				pc.Me.RequestPublicKey("")
			}()

			go func() {
				txa := make(map[string]int64)

				for x := 0; x < 512; x++ {
					ok := false
					time.Sleep(200 * time.Millisecond)
					for k, _ := range pc.AlreadyJoined {
						if txa[k] > 12 {
							continue
						}
						if pc.Me.FP(k) == "" {
							ok = false
							txa[k]++
							pc.Me.RequestPublicKey(k)
							break
						} else {
							ok = true
						}
					}

					if ok {
						pc.CallFunc(JOINED, new(Event))
						pc.allIsWell = true
						break
					}
				}
			}()
		}
	}

	if typ == USERCONNECT && pc.AlreadyJoined[msg.Username] == true {
		return
	} else {
		pc.AlreadyJoined[msg.Username] = true
	}

	if typ == USERQUIT {
		pc.userJoinSent[msg.Username] = false
		pc.AlreadyJoined[msg.Username] = false
	}

	msg.Type = typ
	msg.At = time.Now().UnixNano()
	if pc.interceptor != nil && typ != USERCONNECT {
		if msg.Body != "+ping" || msg.Body != "+pong" {
			if typ == GROUPMESSAGE || typ == PRIVATEMESSAGE {
				if len(msg.Body) < 1024 {
					pc.interceptor(msg)
				}
			} else {
				pc.interceptor(msg)
			}
		}
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

func (pc *PhoxyConn) SendRawGroupMessage(body string) {
	if pc.Opts.Type == WS {
		if pc.WS != nil {
			pc.WS.SendMessage(pc.Opts.Chatroom+"@conference.crypto.dog", "groupchat", body)
		}
	}
}

func (pc *PhoxyConn) GroupMessage(body string) {
	pc.Me.SendMessage([]byte(body))
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

	if pc.Opts.Type == WS {
		pc.WS.Disconnect()
	}
}
