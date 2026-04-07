package scanner

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func TestReadHTTPServerHeaderHandlesSegmentedResponse(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()

	errCh := make(chan error, 1)
	go func() {
		defer close(errCh)
		defer serverConn.Close()

		buf := make([]byte, 256)
		n, err := serverConn.Read(buf)
		if err != nil {
			errCh <- fmt.Errorf("read request: %w", err)
			return
		}
		if got := string(buf[:n]); !strings.Contains(got, "HEAD / HTTP/1.0") {
			errCh <- fmt.Errorf("unexpected request %q", got)
			return
		}

		for _, chunk := range []string{
			"HTTP/1.1 200 OK\r\nSer",
			"ver: nginx\r\nContent-Length: 0\r\n\r\n",
		} {
			if _, err := serverConn.Write([]byte(chunk)); err != nil {
				errCh <- fmt.Errorf("write response chunk: %w", err)
				return
			}
		}
	}()

	got := readHTTPServerHeader(clientConn, "192.0.2.10", "192.0.2.10:80", 500*time.Millisecond)
	if got != "nginx" {
		t.Fatalf("expected server header nginx, got %q", got)
	}

	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
}
