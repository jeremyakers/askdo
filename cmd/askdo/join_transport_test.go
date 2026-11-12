package main

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestFleetJoinInitialTLSFailuresStopPromptly(t *testing.T) {
	for _, mode := range []string{"stalled", "plain-http", "reset"} {
		t.Run(mode, func(t *testing.T) {
			path := fleetJoinHostFixture(t, localJoinConfig)
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			go func() {
				defer close(done)
				for {
					conn, err := listener.Accept()
					if err != nil {
						return
					}
					switch mode {
					case "stalled":
						_, _ = io.Copy(io.Discard, conn)
					case "plain-http":
						_, _ = io.WriteString(conn, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
					}
					conn.Close()
				}
			}()
			defer func() { listener.Close(); <-done }()
			address := "https://" + listener.Addr().String()
			ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
			defer cancel()
			start := time.Now()
			err = runFleetJoin(ctx, []string{address}, path, nil, io.Discard, io.Discard)
			if err == nil || !strings.Contains(err.Error(), "cannot connect to "+address) || !strings.Contains(err.Error(), "TLS handshake") || ctx.Err() != nil || time.Since(start) > 7*time.Second {
				t.Fatalf("initial %s endpoint was retried: %v (elapsed %s, context %v)", mode, err, time.Since(start), ctx.Err())
			}
			if fileContent(t, path) != localJoinConfig {
				t.Fatal("failed TLS changed host config")
			}
		})
	}
}

func TestFleetJoinRejectsExplicitBlankDisplayNames(t *testing.T) {
	path := fleetJoinHostFixture(t, localJoinConfig)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, name := range []string{"", " ", "\t\u00a0"} {
		err := runFleetJoin(ctx, []string{"https://127.0.0.1:1", "--name", name}, path, nil, io.Discard, io.Discard)
		if err == nil || !strings.Contains(err.Error(), "--name must be") {
			t.Errorf("blank %q did not get name remedy: %v", name, err)
		}
	}
}
