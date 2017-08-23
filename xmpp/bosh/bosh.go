package bosh

import (
	"bytes"
	crand "crypto/rand"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"html/template"
	"io"
	"log"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	InitPacket               = `<body rid='{{.RID}}' xmlns='http://jabber.org/protocol/httpbind' to='{{.Domain}}' xml:lang='en' wait='60' hold='1' content='text/xml; charset=utf-8' ver='1.6' xmpp:version='1.0' xmlns:xmpp='urn:xmpp:xbosh'/>`
	ChooseAuthPacket         = `<body rid='{{.RID}}' xmlns='http://jabber.org/protocol/httpbind' sid='{{.SID}}'><auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='ANONYMOUS'/></body>`
	RestartPacket            = `<body rid='{{.RID}}' xmlns='http://jabber.org/protocol/httpbind' sid='{{.SID}}' to='{{.Domain}}' xml:lang='en' xmpp:restart='true' xmlns:xmpp='urn:xmpp:xbosh'/>`
	BindPacket               = `<body rid='{{.RID}}' xmlns='http://jabber.org/protocol/httpbind' sid='{{.SID}}'><iq type='set' id='_bind_auth_2' xmlns='jabber:client'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/></iq></body>`
	SessionAuth2Packet       = `<body rid='{{.RID}}' xmlns='http://jabber.org/protocol/httpbind' sid='{{.SID}}'><iq type='set' id='_session_auth_2' xmlns='jabber:client'><session xmlns='urn:ietf:params:xml:ns:xmpp-session'/></iq></body>`
	JoinMUCPacket            = `<body rid='{{.RID}}' xmlns='http://jabber.org/protocol/httpbind' sid='{{.SID}}'><presence from='{{.JID}}' to='{{.Human}}' xmlns='jabber:client'><x xmlns='http://jabber.org/protocol/muc'><history maxstanzas='0'/></x></presence><presence from='{{.JID}}' to='{{.Human}}' xmlns='jabber:client'><show/><status/></presence></body>`
	JustListeningPacket      = `<body rid='{{.RID}}' xmlns='http://jabber.org/protocol/httpbind' sid='{{.SID}}'/>`
	SendGroupMessagePacket   = `<body rid='{{.RID}}' xmlns='http://jabber.org/protocol/httpbind' sid='{{.SID}}'><message to='{{.Recipient}}' from='{{.JID}}' type='groupchat' id='{{.ID}}' xmlns='jabber:client'><body xmlns='jabber:client'>{{.Message}}</body><x xmlns='jabber:x:event'><active/></x></message></body>`
	SendPrivateMessagePacket = `<body rid='{{.RID}}' xmlns='http://jabber.org/protocol/httpbind' sid='{{.SID}}'><message to='{{.Recipient}}' from='{{.JID}}' type='chat' id='{{.ID}}' xmlns='jabber:client'><body xmlns='jabber:client'>{{.Message}}</body><x xmlns='jabber:x:event'><active/></x></message></body>`
	DisconnectPacket         = `<body rid='{{.RID}}' xmlns='http://jabber.org/protocol/httpbind' sid='{{.SID}}' type='terminate'><presence xmlns='jabber:client' type='unavailable'/></body>`
)

type XTemplate struct {
	Tpl    string
	Packet *XPacket
}

type Config struct {
	BOSHEndpoint     string
	Domain           string
	ConferenceDomain string
	Lobby            string
	HumanName        string
}

type Thing int

const (
	UserJoin Thing = iota
	UserQuit
	ReceivedGroupMessage
	ReceivedPrivateMessage
	Composing
	Paused
)

type XPacket struct {
	RID       int64
	SID       string
	ID        string
	JID       string
	Domain    string
	Human     string
	Recipient string
	Message   string
}

type ResponseBody struct {
	XMLName    xml.Name
	Sid        string `xml:"sid,attr"`
	Wait       int    `xml:"wait,attr"`
	Requests   int    `xml:"requests,attr"`
	Inactivity int    `xml:"inactivity,attr"`
	Maxpause   int    `xml:"maxpause,attr"`
	Polling    int    `xml:"polling,attr"`
	Version    string `xml:"ver,attr"`
	From       string `xml:"from,attr"`
	Secure     bool   `xml:"secure,attr"`
	AuthID     string `xml:"authid,attr"`
	IQ         IQ     `xml:"iq"`
}

type Body struct {
	Name     xml.Name
	Message  []Message  `xml:"message"`
	Presence []Presence `xml:"presence"`
}

type Error struct {
	Code int    `xml:"code,attr"`
	Type string `xml:"type,attr"`
}

type Message struct {
	Type  string `xml:"type,attr"`
	From  string `xml:"from,attr"`
	To    string `xml:"to,attr"`
	Id    string `xml:"id,attr"`
	Body  string `xml:"body"`
	X     Event  `xml:"x"`
	Error *Error `xml:"error"`
}

type Event struct {
	Composing *string `xml:"composing"`
	Paused    *string `xml:"paused"`
}

type IQ struct {
	XMLName xml.Name
	Id      string `xml:"id,attr"`
	Type    string `xml:"type,attr"`
	Bind    Bind   `xml:"bind"`
}

type Bind struct {
	XMLName xml.Name
	JID     string `xml:"jid"`
}

type XMPPEvent struct {
	Type     string
	Username string
	MUC      string
	Message  string
}

type Conn struct {
	Errorchan            chan error
	SendingListenPackets bool
	Conf                 Config
	RID                  int64
	MsgLock              sync.Mutex
	SID                  string
	JID                  string
	send                 chan XTemplate
	recv                 chan string
	keepalive            chan bool
	OnMessage            func(*Conn, *XMPPEvent)

	userState       map[string]bool
	userLock        *sync.Mutex
	started, closed bool

	conns int
	connL *sync.Mutex
}

func randomID() string {
	buf := make([]byte, 32)
	crand.Read(buf)
	return hex.EncodeToString(buf)
}

type ChatIntro struct {
	Body      xml.Name
	Presences []Presence `xml:"presence"`
}

type Presence struct {
	Name  xml.Name
	From  string `xml:"from,attr"`
	To    string `xml:"to,attr"`
	Type  string `xml:"type,attr"`
	Error *Error `xml:"error"`
}

func randFloat() float64 {
	rand.Seed(time.Now().UTC().UnixNano())
	return rand.Float64()
}

func newRID() int64 {
	return int64(1000000000 + randFloat()*9000000000)
}

func IsElem(element string, array []string) bool {
	for _, v := range array {
		if v == element {
			return true
		}
	}

	return false
}

func IsPosElem(element string, array []string) (bool, int) {
	for i, v := range array {
		if v == element {
			return true, i
		}
	}

	return false, -1
}

func Unmarshal(s string) ResponseBody {
	var rb ResponseBody
	err := xml.Unmarshal([]byte(s), &rb)
	if err != nil {
		log.Fatal(err)
	}

	return rb
}

func (x XPacket) Render(tpl string) string {
	var buf bytes.Buffer
	t, err := template.New("tpl").Parse(tpl)
	if err != nil {
		log.Fatal(err)
	}
	err = t.Execute(&buf, x)
	if err != nil {
		log.Fatal(err)
	}
	return buf.String()
}

func NewConversation(c *Config, onmessage func(*Conn, *XMPPEvent)) error {
	conn, err := NewConn(*c)
	if err != nil {
		return err
	}

	conn.Errorchan = make(chan error)
	conn.OnMessage = onmessage

	conn.JoinMUC(c.Lobby)

	// go func() {
	// 	time.Sleep(5 * time.Second)
	// 	conn.SendGroupMessage("Hello World")
	// }()

	// conn.keepalive <- true

	go func() {
		for {
			str := <-conn.recv
			err := conn.DecodeMessage(str)
			if err != nil {
				conn.Errorchan <- err
				continue
			}
		}
	}()

	return <-conn.Errorchan
}

func (conn *Conn) DecodeMessage(msg string) error {
	var x Body
	x.Name = xml.Name{Space: "http://jabber.org/protocol/httpbind", Local: "body"}
	err := xml.Unmarshal([]byte(msg), &x)
	if err != nil {
		return err
	}

	for _, msg := range x.Message {
		if msg.Error != nil {
			return fmt.Errorf("Error code %d", msg.Error.Code)
		}

		nameel := strings.Split(msg.From, "/")
		if len(nameel) != 2 {
			return fmt.Errorf("Invalid name")
		}

		name := nameel[1]
		muc := strings.Split(msg.From, "@")[0]

		if msg.Body != "" {
			if msg.Type == "groupchat" {
				go conn.OnMessage(conn, &XMPPEvent{
					Type:     "GroupchatMessageReceived",
					Username: name,
					MUC:      muc,
					Message:  msg.Body,
				})
			}

			if msg.Type == "chat" {
				go conn.OnMessage(conn, &XMPPEvent{
					Type:     "PrivateMessageReceived",
					Username: name,
					MUC:      muc,
					Message:  msg.Body,
				})
			}
		}

		if msg.X.Composing != nil {
			go conn.OnMessage(conn, &XMPPEvent{
				Type:     "Composing",
				Username: name,
				MUC:      muc,
			})
		}

		if msg.X.Paused != nil {
			go conn.OnMessage(conn, &XMPPEvent{
				Type:     "Paused",
				Username: name,
				MUC:      muc,
			})
		}
	}

	conn.userLock.Lock()
	for _, pres := range x.Presence {
		name := strings.Split(pres.From, "/")[1]

		if pres.Type == "error" {
			if pres.Error.Code == 409 {
				conn.Errorchan <- fmt.Errorf("Nickname in use")
			}
		}

		if pres.Type == "unavailable" {
			if conn.userState[name] == true {
				conn.userState[name] = false
				go conn.OnMessage(conn, &XMPPEvent{
					Type:     "UserQuit",
					Username: name,
					MUC:      conn.Conf.Lobby,
				})
			}
		}

		if pres.Type == "" {
			if conn.userState[name] == false {
				conn.userState[name] = true
				go conn.OnMessage(conn, &XMPPEvent{
					Type:     "UserJoin",
					Username: name,
					MUC:      conn.Conf.Lobby,
				})
			}
		}
	}
	conn.userLock.Unlock()

	return nil
}

func (conn *Conn) SendTemplate(temp *XTemplate) {
	conn.send <- *temp
}

func (conn *Conn) SendGroupMessage(msg string) {
	conn.SendTemplate(&XTemplate{
		Packet: &XPacket{
			RID:       conn.RID,
			JID:       conn.JID,
			SID:       conn.SID,
			Domain:    conn.Conf.Domain,
			Recipient: conn.Conf.Lobby + "@" + conn.Conf.ConferenceDomain,
			Message:   msg,
			ID:        randomID(),
		},
		Tpl: SendGroupMessagePacket,
	})
}

func (conn *Conn) Post(client *http.Client, url, payload string) <-chan string {
	d := make(chan string)
	go func() {
		conn.connL.Lock()
		conn.conns++
		conn.connL.Unlock()
		post, err := http.NewRequest("POST", url, strings.NewReader(payload))
		if err != nil {
			d <- ""
			conn.Errorchan <- err
			return
		}
		post.Header.Set("Content-Type", "text/plain; charset=UTF-8")
		post.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 6.1; rv:52.0) Gecko/20100101 Firefox/52")
		r, err := client.Do(post)
		if err != nil {
			conn.connL.Lock()
			conn.conns--
			conn.connL.Unlock()
			d <- ""
			conn.Errorchan <- err
			return
		}

		conn.connL.Lock()
		conn.conns--
		conn.connL.Unlock()

		var b bytes.Buffer
		io.Copy(&b, r.Body)
		r.Body.Close()
		// log.Println(r.StatusCode, blo.String())

		if r.StatusCode != 200 {
			d <- ""
			conn.keepalive <- true
			return
		}

		d <- b.String()
	}()

	return d
}

func NewConn(c Config) (*Conn, error) {
	tr := &http.Transport{}
	client := &http.Client{
		Transport: tr,
		Timeout:   1000 * time.Second,
	}

	conn := &Conn{}
	conn.Conf = c
	conn.RID = newRID()
	conn.userLock = new(sync.Mutex)
	conn.userState = make(map[string]bool)

	conn.connL = new(sync.Mutex)
	conn.send = make(chan XTemplate, 128)
	conn.recv = make(chan string, 128)
	conn.keepalive = make(chan bool, 128)
	go func() {
		for {
			if conn.closed == true {
				return
			}
			conn.connL.Lock()
			time.Sleep(20*time.Millisecond + (time.Duration(conn.conns) * 100 * time.Millisecond))
			conn.connL.Unlock()
			conn.RID++
			var pcket string
			pc := XPacket{
				RID:    conn.RID,
				SID:    conn.SID,
				Domain: c.Domain,
			}
			pcket = pc.Render(JustListeningPacket)

			if conn.started {
				select {
				case tpl := <-conn.send:
					tpl.Packet.RID = conn.RID
					pcket = tpl.Packet.Render(tpl.Tpl)
					go func() {
						<-conn.keepalive
					}()
				case <-conn.keepalive:
				}
			} else {
				tpl := <-conn.send
				tpl.Packet.RID = conn.RID
				pcket = tpl.Packet.Render(tpl.Tpl)
			}
			go func(pk string) {
				str := <-conn.Post(client, conn.Conf.BOSHEndpoint, pk)
				if str != "" {
					conn.recv <- str
					if conn.started && str != `<body xmlns='http://jabber.org/protocol/httpbind'/>` {
						conn.keepalive <- true
					}
				}
			}(pcket)
		}
	}()
	// Initialize login
	conn.send <- XTemplate{
		Packet: &XPacket{
			RID:    conn.RID,
			Domain: c.Domain,
		},
		Tpl: InitPacket,
	}

	str := <-conn.recv

	conn.SID = Unmarshal(str).Sid

	// Select anonymous auth
	conn.send <- XTemplate{
		Packet: &XPacket{
			RID:    conn.RID,
			SID:    conn.SID,
			Domain: conn.Conf.Domain,
		},
		Tpl: ChooseAuthPacket,
	}

	str = <-conn.recv

	conn.send <- XTemplate{
		Packet: &XPacket{
			RID:    conn.RID,
			SID:    conn.SID,
			Domain: conn.Conf.Domain,
		}, Tpl: RestartPacket,
	}

	str = <-conn.recv

	conn.send <- XTemplate{
		Packet: &XPacket{
			RID:    conn.RID,
			SID:    conn.SID,
			Domain: conn.Conf.Domain,
		}, Tpl: BindPacket}

	str = <-conn.recv

	// Now, we get our JID.

	xpack := Unmarshal(str)
	conn.JID = xpack.IQ.Bind.JID

	conn.send <- XTemplate{Packet: &XPacket{
		RID:    conn.RID,
		SID:    conn.SID,
		Domain: conn.Conf.Domain,
	}, Tpl: SessionAuth2Packet}
	str = <-conn.recv

	conn.started = true
	conn.keepalive <- true
	return conn, nil
}

func (conn *Conn) JoinMUC(mucname string) {
	pc := XPacket{
		RID:    conn.RID,
		JID:    conn.JID,
		SID:    conn.SID,
		Domain: conn.Conf.Domain,
	}

	pc.Human = mucname + "@" + conn.Conf.ConferenceDomain + "/" + conn.Conf.HumanName

	conn.send <- XTemplate{Packet: &pc, Tpl: JoinMUCPacket}
}

func (conn *Conn) Disconnect() {
	pc := XPacket{
		RID:    conn.RID,
		JID:    conn.JID,
		SID:    conn.SID,
		Domain: conn.Conf.Domain,
	}
	conn.send <- XTemplate{Packet: &pc, Tpl: DisconnectPacket}
	time.Sleep(4 * time.Second)
	conn.closed = true
}
