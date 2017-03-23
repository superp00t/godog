// +build js

package ws

import (
	"fmt"

	"github.com/gopherjs/gopherjs/js"
	"github.com/gopherjs/websocket"
)

type JSConn struct {
	StatusCode int

	Conn *websocket.WebSocket

	RecvChan chan string
	Die      chan error
	Ok       chan bool
}

func (jc *JSConn) Close() error {
	return jc.Conn.Close()
}

func (jc *JSConn) Status() int {
	return 200
}

func (jc *JSConn) Recv() (string, error) {
	select {
	case data := <-jc.RecvChan:
		return data, nil
	case err := <-jc.Die:
		return "", err
	}
}

func (jc *JSConn) Send(data string) error {
	return jc.Conn.Send(data)
}

func DialConn(url string) (Conn, error) {
	jc := &JSConn{}
	jc.Ok = make(chan bool)
	jc.RecvChan = make(chan string, 16)
	jc.Die = make(chan error)
	object := js.Global.Get("WebSocket").New(url, "xmpp")

	ws := &websocket.WebSocket{
		Object: object,
	}

	jc.Conn = ws

	jc.Conn.AddEventListener("message", false, func(j *js.Object) {
		jc.RecvChan <- j.Get("data").String()
	})

	jc.Conn.AddEventListener("error", false, func(j *js.Object) {
		jc.Die <- fmt.Errorf("Unknown error")
	})

	jc.Conn.AddEventListener("open", false, func(j *js.Object) {
		jc.Ok <- true
	})

	select {
	case err := <-jc.Die:
		return nil, err
	case <-jc.Ok:
		return jc, nil
	}
}
