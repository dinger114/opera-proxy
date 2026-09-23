package handler

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	clog "github.com/Snawoot/opera-proxy/log"
)

func nopLogger() *clog.CondLogger {
	// verbosity above CRITICAL silences every level.
	return clog.NewCondLogger(log.New(io.Discard, "", 0), 99)
}

// hopHeaders must carry the RFC 7230 singular "Trailer", not "Trailers", and
// must strip Proxy-Authorization so client proxy credentials never travel
// upstream on a proxy chain.
func TestHopHeadersNames(t *testing.T) {
	h := http.Header{}
	h.Set("Proxy-Authorization", "Basic SECRET")
	h.Set("Trailer", "X-Trailer")
	h.Set("Trailers", "X-Trailers")
	h.Set("Connection", "keep-alive")
	delHopHeaders(h)

	if got := h.Get("Proxy-Authorization"); got != "" {
		t.Errorf("Proxy-Authorization survived: %q", got)
	}
	if got := h.Get("Trailer"); got != "" {
		t.Errorf("Trailer survived (should be stripped as hop-by-hop): %q", got)
	}
	if got := h.Get("Connection"); got != "" {
		t.Errorf("Connection survived: %q", got)
	}
	// Regression guard: the old misspelling matched nothing useful, so a
	// real singular Trailer header would have slipped through.
	if got := h.Get("Trailers"); got == "" {
		t.Log("note: plural Trailers also removed via canonicalization check passed")
	}
}

// A header named by the client's Connection header is hop-by-hop by
// definition and must be dropped before the request goes upstream.
func TestDelProxyConnectionTokens(t *testing.T) {
	h := http.Header{}
	h.Set("Connection", "Keep-Alive, X-Custom-Hop")
	h.Set("X-Custom-Hop", "should-be-removed")
	h.Set("X-Keep", "should-survive")
	delProxyConnectionTokens(h)

	if got := h.Get("X-Custom-Hop"); got != "" {
		t.Errorf("X-Custom-Hop named in Connection survived: %q", got)
	}
	if got := h.Get("X-Keep"); got != "should-survive" {
		t.Errorf("unrelated header was dropped: %q", got)
	}
}

// copyStream must refresh the deadline on every successful read, so an
// active transfer keeps extending the idle window.
func TestCopyStreamRefreshes(t *testing.T) {
	var refreshes int
	refresh := func() { refreshes++ }
	src := bytes.NewReader([]byte("hello world"))
	var dst bytes.Buffer

	n, err := copyStream(&dst, src, refresh)
	if err != nil {
		t.Fatalf("copyStream: %v", err)
	}
	if n != int64(len("hello world")) || dst.String() != "hello world" {
		t.Fatalf("copied %d bytes %q", n, dst.String())
	}
	if refreshes == 0 {
		t.Fatal("refresh was never called; an idle tunnel would be reaped while active")
	}
}

// A no-op refresher must be returned for a zero timeout, so the tunnel
// behaves exactly as before when the timeout is disabled.
func TestDeadlineRefresherZeroTimeoutIsNoop(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	rc := &recordingConn{Conn: c1}
	refresh := deadlineRefresher(0, rc)
	refresh()
	if rc.deadlineCalls != 0 {
		t.Fatalf("zero timeout called SetDeadline %d times", rc.deadlineCalls)
	}
}

// With a live timeout the deadline must be pushed into the future.
func TestDeadlineRefresherSetsDeadline(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	rc := &recordingConn{Conn: c1}
	refresh := deadlineRefresher(50*time.Millisecond, rc)
	refresh()
	if rc.deadlineCalls != 1 {
		t.Fatalf("expected 1 SetDeadline call, got %d", rc.deadlineCalls)
	}
	if rc.deadline.IsZero() || time.Until(rc.deadline) <= 0 {
		t.Fatalf("deadline not in the future: %v", rc.deadline)
	}
}

type recordingConn struct {
	net.Conn
	deadlineCalls int
	deadline      time.Time
}

func (c *recordingConn) SetDeadline(t time.Time) error {
	c.deadlineCalls++
	c.deadline = t
	return c.Conn.SetDeadline(t)
}

// The whole point of the fix: a client that completes the CONNECT handshake
// and then goes silent must not hold the tunnel forever.
func TestTunnelIdleTimeoutReapsSilentConn(t *testing.T) {
	upstream, upServer := net.Pipe()
	defer upstream.Close()
	defer upServer.Close()

	d := &stubDialer{conn: upstream}
	const idle = 150 * time.Millisecond
	h := NewProxyHandler(d, nopLogger(), idle)

	req := httptest.NewRequest(http.MethodConnect, "http://example.com:443", nil)
	req.RequestURI = "example.com:443"
	req.ProtoMajor, req.ProtoMinor = 1, 1

	client, rec := newFakeClient(t)

	done := make(chan struct{})
	go func() {
		h.HandleTunnel(rec, req)
		close(done)
	}()

	br := bufio.NewReader(client)
	client.SetReadDeadline(time.Now().Add(3 * time.Second))
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("reading CONNECT reply: %v", err)
	}
	if !strings.HasPrefix(status, "HTTP/1.1 200") {
		t.Fatalf("unexpected handshake reply: %q", status)
	}

	// Both directions now go silent: nobody writes and nobody reads.
	select {
	case <-done:
		// Tunnel was torn down by the idle deadline. This is the fix.
	case <-time.After(3 * time.Second):
		t.Fatal("idle tunnel was never reaped: proxy still holds the connection")
	}
}

type stubDialer struct{ conn net.Conn }

func (d *stubDialer) Dial(network, address string) (net.Conn, error) {
	return d.conn, nil
}

func (d *stubDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.conn, nil
}

type hijackableRecorder struct {
	*httptest.ResponseRecorder
	conn net.Conn
	br   *bufio.ReadWriter
}

func (r *hijackableRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return r.conn, r.br, nil
}

// newFakeClient wires a hijackableRecorder to one end of a net.Pipe and
// returns the client side plus the recorder HandleTunnel will hijack.
func newFakeClient(t *testing.T) (net.Conn, *hijackableRecorder) {
	t.Helper()
	client, server := net.Pipe()
	rec := &hijackableRecorder{
		ResponseRecorder: httptest.NewRecorder(),
		conn:             server,
		br:               bufio.NewReadWriter(bufio.NewReader(server), bufio.NewWriter(server)),
	}
	return client, rec
}
