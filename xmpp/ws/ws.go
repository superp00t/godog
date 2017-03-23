package ws

// Conn defines the abstraction of a WebSocket connection between Gopherjs and TCP-capable platforms
type Conn interface {
	Recv() (string, error)
	Send(string) error
	Status() int
	Close() error
}
