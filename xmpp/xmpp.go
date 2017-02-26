package xmpp

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"html/template"
	"net/url"
	"strings"

	"golang.org/x/net/websocket"
)

const (
	OpenStanza        = "<open xmlns='urn:ietf:params:xml:ns:xmpp-framing' to='{{.Host}}' version='1.0'/>"
	AuthStanza        = "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='ANONYMOUS'/>"
	BindStanza        = "<iq type='set' id='_bind_auth_2' xmlns='jabber:client'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/></iq>"
	SessStanza        = "<iq type='set' id='_session_auth_2' xmlns='jabber:client'><session xmlns='urn:ietf:params:xml:ns:xmpp-session'/></iq>"
	JoinMucStanza     = "<presence from='{{.JID}}' to='{{.MUCJID}}' xmlns='jabber:client'><x xmlns='http://jabber.org/protocol/muc'/></presence>"
	JoinMucStanza2    = "<presence from='{{.JID}}' to='{{.MUCJID}}' xmlns='jabber:client'><show/><status/></presence>"
	SendMessageStanza = "<message to='{{.Recipient}}' from='{{.JID}}' type='{{.Type}}' xmlns='jabber:client'><body xmlns='jabber:client'>{{.Body}}</body><x xmlns='jabber:x:event'><active/></x></message>"
)

type Presence struct {
	Presence xml.Name
	From     string `xml:"from,attr"`
	To       string `xml:"to,attr"`
	Type     string `xml:"type,attr"`
}

type Message struct {
	Message xml.Name
	Type    string `xml:"type,attr"`
	From    string `xml:"from,attr"`
	To      string `xml:"to,attr"`
	Id      string `xml:"id,attr"`
	Body    string `xml:"body"`
	Error   Error  `xml:"error"`
	X       Event  `xml:"x"`
}

type Error struct {
	Code int `xml:"code"`
}
type Event struct {
	Composing *string `xml:"composing"`
	Paused    *string `xml:"paused"`
}

type Stanza struct {
	Host      string
	JID       string
	MUCJID    string
	Recipient string
	Type      string
	Body      string
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

type Opts struct {
	WSURL              string
	Host               string
	Username, Password string
	Debug              bool
}

type Client struct {
	JID  string
	Opts Opts
	Sock *websocket.Conn
}

func (s Stanza) Render(st string) string {
	t, err := template.New("stanza").Parse(st)
	if err != nil {
		panic(err)
	}

	var bf bytes.Buffer
	err = t.Execute(&bf, s)
	if err != nil {
		panic(err)
	}

	return bf.String()
}

func (o Opts) Connect() (*Client, error) {
	u, err := url.Parse(o.WSURL)
	if err != nil {
		return nil, err
	}

	u.Scheme = "https"
	u.Path = "/"

	c, err := websocket.Dial(o.WSURL, "xmpp", u.String())
	if err != nil {
		return nil, err
	}

	cli := &Client{
		Sock: c,
		Opts: o,
	}

	if o.Username == "" {
		cli.send(Stanza{Host: o.Host}.Render(OpenStanza))
	} else {
		return nil, fmt.Errorf("Authenticated login not yet implemented")
	}

	cli.recv()
	cli.recv()
	cli.send(AuthStanza)
	cli.recv()
	cli.send(Stanza{Host: o.Host}.Render(OpenStanza))
	cli.recv()
	cli.recv()
	cli.send(BindStanza)
	var i IQ
	i.XMLName = xml.Name{Local: "iq", Space: "jabber:client"}
	str, _ := cli.recv()
	err = xml.Unmarshal([]byte(str), &i)
	if err != nil {
		return nil, err
	}

	cli.JID = i.Bind.JID
	cli.send(SessStanza)
	cli.recv()

	return cli, nil
}

func (c *Client) send(stanza string) error {
	err := websocket.Message.Send(c.Sock, stanza)
	if err != nil {
		return err
	}

	if c.Opts.Debug {
		fmt.Printf("send\t%s\n", stanza)
	}
	return nil
}

func (c *Client) recv() (string, error) {
	var stanza string
	err := websocket.Message.Receive(c.Sock, &stanza)
	if err != nil {
		return "", err
	}

	if c.Opts.Debug {
		fmt.Printf("recv\t%s\n", stanza)
	}

	return stanza, nil
}

func (c *Client) JoinMUC(jid, nick string) {
	mjid := jid + "/" + nick
	c.send(Stanza{JID: c.JID, MUCJID: mjid}.Render(JoinMucStanza))
	c.send(Stanza{JID: c.JID, MUCJID: mjid}.Render(JoinMucStanza2))
}

func (c *Client) Recv() (interface{}, error) {
	str, err := c.recv()
	if err != nil {
		return nil, err
	}

	if strings.HasPrefix(str, "<presence") {
		var pres Presence
		pres.Presence = xml.Name{Local: "presence", Space: "jabber:client"}
		xml.Unmarshal([]byte(str), &pres)
		if pres.Type == "error" {
			return nil, fmt.Errorf("Username already taken")
		}
		return pres, nil
	}

	if strings.HasPrefix(str, "<message") {
		var msg Message
		msg.Message = xml.Name{Local: "message", Space: "jabber:client"}
		xml.Unmarshal([]byte(str), &msg)
		if msg.Type == "error" {
			return nil, fmt.Errorf("Username already taken")
		}
		return msg, nil
	}

	return nil, fmt.Errorf("Unknown thing")
}

func (c *Client) SendMessage(jid, typeof, body string) {
	c.send(Stanza{
		Recipient: jid,
		Type:      typeof,
		Body:      body,
		JID:       c.JID,
	}.Render(SendMessageStanza))
}
