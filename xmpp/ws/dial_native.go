// +build !js

package ws

import (
	"fmt"
	"sync"

	"github.com/gorilla/websocket"
	"golang.org/x/net/proxy"
)

type NativeConn struct {
	StatusCode int

	Conn *websocket.Conn

	RecvChan chan string
	Die      chan error

	l *sync.Mutex
}

func (jc *NativeConn) Status() int {
	return jc.StatusCode
}

func (jc *NativeConn) Close() error {
	return jc.Conn.Close()
}

func (jc *NativeConn) Recv() (string, error) {
	select {
	case data := <-jc.RecvChan:
		return data, nil
	case err := <-jc.Die:
		return "", err
	}
}

func (jc *NativeConn) Send(data string) error {
	defer jc.l.Unlock()
	jc.l.Lock()
	return jc.Conn.WriteMessage(websocket.TextMessage, []byte(data))
}

func DialConn(url string, proxyaddr string) (Conn, error) {
	jc := &NativeConn{}
	jc.RecvChan = make(chan string, 16)
	jc.Die = make(chan error)
	var ws *websocket.Conn
	jc.l = new(sync.Mutex)

	if proxyaddr != "" {
		fmt.Println("Connecting with proxy", proxyaddr)
		netDialer, err := proxy.SOCKS5("tcp", proxyaddr, nil, proxy.Direct)
		if err != nil {
			return nil, err
		}
		dialer := websocket.Dialer{NetDial: netDialer.Dial}
		ws, _, err = dialer.Dial(url, nil)
		if err != nil {
			return nil, err
		}
	} else {
		var err error
		ws, _, err = websocket.DefaultDialer.Dial(url, nil)
		if err != nil {
			return nil, err
		}
	}

	jc.Conn = ws

	go func() {
		for {
			_, b, err := ws.ReadMessage()
			buf := string(b)
			if err != nil {
				jc.Die <- err
				break
			}
			jc.RecvChan <- buf
		}
	}()

	return jc, nil
}
