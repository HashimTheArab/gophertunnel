package minecraft

import (
	"log/slog"
	"net"
	"testing"
)

func TestTransportAbortAndGracefulCloseStayDistinct(t *testing.T) {
	for _, immediate := range []bool{false, true} {
		name := "graceful"
		if immediate {
			name = "abort"
		}
		t.Run(name, func(t *testing.T) {
			transport := &abortObservedTransport{}
			conn := newConn(transport, nil, slog.New(slog.DiscardHandler), DefaultProtocol, -1, false)
			if _, err := conn.Write([]byte{1}); err != nil {
				t.Fatal(err)
			}
			var err error
			if immediate {
				err = conn.Abort()
			} else {
				err = conn.Close()
			}
			if err != nil {
				t.Fatal(err)
			}
			if immediate {
				if transport.aborts != 1 || transport.closes != 0 || transport.writes != 0 {
					t.Fatalf("Abort flushed data or used graceful transport closure: %+v", transport)
				}
			} else if transport.closes != 1 || transport.aborts != 0 || transport.writes != 1 {
				t.Fatalf("Close failed to flush before graceful transport closure: %+v", transport)
			}
			if conn.Context().Err() == nil {
				t.Fatal("termination left the connection context active")
			}
		})
	}
}

func TestAbortFinishesGracefulTransportTeardown(t *testing.T) {
	transport := &abortObservedTransport{}
	conn := newConn(transport, nil, slog.New(slog.DiscardHandler), DefaultProtocol, -1, false)
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := conn.Abort(); err != nil {
			t.Fatal(err)
		}
	}
	if transport.closes != 1 || transport.aborts != 1 {
		t.Fatalf("Abort failed to finish graceful transport teardown once: %+v", transport)
	}
}

type abortObservedTransport struct {
	net.Conn
	writes, closes, aborts int
}

func (conn *abortObservedTransport) Write(data []byte) (int, error) {
	conn.writes++
	return len(data), nil
}

func (conn *abortObservedTransport) Close() error {
	conn.closes++
	return nil
}

func (conn *abortObservedTransport) Abort() error {
	conn.aborts++
	return nil
}

func (conn *abortObservedTransport) RemoteAddr() net.Addr { return &net.UDPAddr{} }
func (conn *abortObservedTransport) LocalAddr() net.Addr  { return &net.UDPAddr{} }
