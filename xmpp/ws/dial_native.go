// +build !js

package ws

import "golang.org/x/net/websocket"

type NativeConn struct {
	StatusCode int

	Conn *websocket.Conn

	RecvChan chan string
	Die      chan error
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
	return websocket.Message.Send(jc.Conn, data)
}

func DialConn(url string) (Conn, error) {
	jc := &NativeConn{}
	jc.RecvChan = make(chan string, 16)
	jc.Die = make(chan error)
	ws, err := websocket.Dial(url, "xmpp", "http://localhost/")
	if err != nil {
		return nil, err
	}

	jc.Conn = ws

	go func() {
		for {
			var buf string
			err := websocket.Message.Receive(jc.Conn, &buf)
			if err != nil {
				jc.Die <- err
				break
			}
			jc.RecvChan <- buf
		}
	}()

	return jc, nil
}
