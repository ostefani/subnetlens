// Copyright (c) 2026 Olha Stefanishyna. MIT License.
package tcp

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/ostefani/subnetlens/models"
	"github.com/ostefani/subnetlens/scanner/contracts"
)

type stubRuntime struct{}

func (stubRuntime) SocketLimiter() contracts.SocketLimiter { return nil }
func (stubRuntime) AcquireScanSlot(context.Context) error  { return nil }
func (stubRuntime) ReleaseScanSlot()                       {}
func (stubRuntime) ReportIssue(models.ScanIssue)           {}

func TestScanHostMarksHostAliveWhenPortIsOpen(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err == nil {
			_ = conn.Close()
		}
	}()

	host := models.NewHost("127.0.0.1")
	host.SetWeak(true)

	_, portStr, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}

	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		t.Fatalf("parse port: %v", err)
	}

	NewHostScanner().ScanHost(context.Background(), host, models.ScanOptions{
		Ports:   []int{port},
		Timeout: 500 * time.Millisecond,
	}, stubRuntime{})

	<-done

	snapshot := host.Snapshot()
	if !snapshot.Alive {
		t.Fatal("expected host with open TCP port to be alive")
	}
	if snapshot.Weak {
		t.Fatal("expected open TCP port to clear weak state")
	}
	if len(snapshot.OpenPorts()) != 1 || snapshot.OpenPorts()[0].Number != port {
		t.Fatalf("expected scanned open port to be recorded, got %+v", snapshot.OpenPorts())
	}
}
