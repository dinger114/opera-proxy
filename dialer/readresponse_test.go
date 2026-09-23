package dialer

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// readResponse must consume exactly the status line + headers and stop at the
// blank line, leaving anything after it on the wire (the tunnel payload).
func TestReadResponseStopsAtHeaderEnd(t *testing.T) {
	raw := "HTTP/1.1 200 Connection established\r\n" +
		"Proxy-Agent: test\r\n" +
		"\r\n" +
		"TRAILING-PAYLOAD"
	req, _ := http.NewRequest("CONNECT", "http://example.com:443", nil)

	resp, err := readResponse(strings.NewReader(raw), req)
	if err != nil {
		t.Fatalf("readResponse: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Proxy-Agent"); got != "test" {
		t.Fatalf("Proxy-Agent = %q", got)
	}
}

// An upstream that accepts the connection and then never replies must fail
// within the deadline instead of blocking forever. Before the fix the
// byte-at-a-time loop had no way to be interrupted and leaked the goroutine.
// tlsServerName is empty so this is the plain-CONNECT path, skipping the TLS
// handshake and exercising readResponse directly.
func TestDialContextDeadlineOnSilentUpstream(t *testing.T) {
	// Upstream that never writes anything.
	srv, cli := net.Pipe()
	defer srv.Close()
	defer cli.Close()

	const timeout = 200 * time.Millisecond
	d := NewProxyDialer(
		WrapStringToCb("127.0.0.1:1"),
		WrapStringToCb(""),
		WrapStringToCb(""),
		nil,
		nil,
		&pipeDialer{conn: cli},
		timeout,
	)

	start := time.Now()
	done := make(chan error, 1)
	go func() {
		_, err := d.DialContext(context.Background(), "tcp", "example.com:443")
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected an error from a silent upstream, got nil")
		}
		elapsed := time.Since(start)
		if elapsed > 3*time.Second {
			t.Fatalf("took %v, deadline was not applied", elapsed)
		}
		t.Logf("silent upstream failed after %v with: %v", elapsed.Round(time.Millisecond), err)
	case <-time.After(5 * time.Second):
		t.Fatal("DialContext hung on a silent upstream: deadline not enforced")
	}
}

// readResponse on its own must not outlive the deadline installed on the
// connection it reads from.
func TestReadResponseRespectsDeadline(t *testing.T) {
	_, cli := net.Pipe()
	defer cli.Close()

	if err := cli.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	req, _ := http.NewRequest("CONNECT", "http://example.com:443", nil)

	start := time.Now()
	_, err := readResponse(cli, req)
	if err == nil {
		t.Fatal("expected an error from a silent upstream")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("readResponse blocked %v despite the deadline", elapsed)
	}
	t.Logf("returned after %v: %v", time.Since(start).Round(time.Millisecond), err)
}

// The caller's tunnel must not inherit a stale deadline, otherwise a healthy
// long-lived tunnel would be killed mid-transfer.
func TestDeadlineLiftedOnSuccess(t *testing.T) {
	// A real TCP listener avoids the synchronous-write subtleties of net.Pipe.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		// Read the CONNECT request, then answer 200 and go idle.
		br := bufio.NewReader(c)
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			if strings.TrimSpace(line) == "" {
				break
			}
		}
		c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		// Hold the connection open and idle, well past the dialer timeout.
		io.Copy(io.Discard, c)
	}()

	d := NewProxyDialer(
		WrapStringToCb(ln.Addr().String()),
		WrapStringToCb(""), // plain CONNECT: no TLS, same deadline handling
		WrapStringToCb(""),
		nil,
		nil,
		&netDialer{},
		80*time.Millisecond,
	)

	conn, err := d.DialContext(context.Background(), "tcp", "example.com:443")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	// Wait past the dialer timeout. If the CONNECT deadline were still armed,
	// the subsequent write would fail; a healthy tunnel must survive.
	time.Sleep(200 * time.Millisecond)
	if err := conn.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	if _, err := conn.Write([]byte("x")); err != nil {
		t.Fatalf("write after timeout: %v (stale deadline left on the tunnel)", err)
	}
}

type netDialer struct{}

func (d *netDialer) Dial(network, address string) (net.Conn, error) {
	return net.Dial(network, address)
}
func (d *netDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, address)
}

// An oversized upstream header block must be rejected rather than buffered
// indefinitely.
func TestReadResponseHeaderCap(t *testing.T) {
	var b strings.Builder
	b.WriteString("HTTP/1.1 200 OK\r\n")
	// One oversized header line.
	b.WriteString("X-Big: ")
	b.WriteString(strings.Repeat("A", MAX_PROXY_RESPONSE_HEADER+1))
	b.WriteString("\r\n\r\n")
	req, _ := http.NewRequest("CONNECT", "http://example.com:443", nil)

	_, err := readResponse(strings.NewReader(b.String()), req)
	if err == nil {
		t.Fatal("expected an error for an oversized header block")
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Fatalf("expected a 'too large' error, got: %v", err)
	}
}

type pipeDialer struct{ conn net.Conn }

func (d *pipeDialer) Dial(network, address string) (net.Conn, error) { return d.conn, nil }
func (d *pipeDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.conn, nil
}
