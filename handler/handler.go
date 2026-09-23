package handler

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Snawoot/opera-proxy/dialer"
	clog "github.com/Snawoot/opera-proxy/log"
)

const (
	COPY_BUF    = 128 * 1024
	BAD_REQ_MSG = "Bad Request\n"
)

type ProxyHandler struct {
	logger        *clog.CondLogger
	dialer        dialer.ContextDialer
	httptransport http.RoundTripper
	idleTimeout   time.Duration
}

func NewProxyHandler(dialer dialer.ContextDialer, logger *clog.CondLogger, idleTimeout time.Duration) *ProxyHandler {
	httptransport := &http.Transport{
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DialContext:           dialer.DialContext,
	}
	return &ProxyHandler{
		logger:        logger,
		dialer:        dialer,
		httptransport: httptransport,
		idleTimeout:   idleTimeout,
	}
}

func (s *ProxyHandler) HandleTunnel(wr http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	conn, err := s.dialer.DialContext(ctx, "tcp", req.RequestURI)
	if err != nil {
		s.logger.Error("Can't satisfy CONNECT request: %v", err)
		http.Error(wr, "Can't satisfy CONNECT request", http.StatusBadGateway)
		return
	}

	if req.ProtoMajor == 0 || req.ProtoMajor == 1 {
		// Upgrade client connection
		localconn, _, err := hijack(wr, s.idleTimeout)
		if err != nil {
			s.logger.Error("Can't hijack client connection: %v", err)
			conn.Close()
			http.Error(wr, "Can't hijack client connection", http.StatusInternalServerError)
			return
		}
		defer localconn.Close()

		// Inform client connection is built
		fmt.Fprintf(localconn, "HTTP/%d.%d 200 OK\r\n\r\n", req.ProtoMajor, req.ProtoMinor)

		proxy(req.Context(), localconn, conn, s.idleTimeout)
	} else if req.ProtoMajor == 2 {
		wr.Header()["Date"] = nil
		wr.WriteHeader(http.StatusOK)
		flush(wr)
		proxyh2(req.Context(), req.Body, wr, conn, s.idleTimeout)
	} else {
		s.logger.Error("Unsupported protocol version: %s", req.Proto)
		http.Error(wr, "Unsupported protocol version.", http.StatusBadRequest)
		return
	}
}

func (s *ProxyHandler) HandleRequest(wr http.ResponseWriter, req *http.Request) {
	req.RequestURI = ""
	if req.ProtoMajor == 2 {
		req.URL.Scheme = "http" // We can't access :scheme pseudo-header, so assume http
		req.URL.Host = req.Host
	}
	resp, err := s.httptransport.RoundTrip(req)
	if err != nil {
		s.logger.Error("HTTP fetch error: %v", err)
		http.Error(wr, "Server Error", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	s.logger.Info("%v %v %v %v", req.RemoteAddr, req.Method, req.URL, resp.Status)
	delHopHeaders(resp.Header)
	copyHeader(wr.Header(), resp.Header)
	wr.WriteHeader(resp.StatusCode)
	flush(wr)
	copyBody(wr, resp.Body, func() {})
}

func (s *ProxyHandler) ServeHTTP(wr http.ResponseWriter, req *http.Request) {
	s.logger.Info("Request: %v %v %v %v", req.RemoteAddr, req.Proto, req.Method, req.URL)

	isConnect := strings.ToUpper(req.Method) == "CONNECT"
	if (req.URL.Host == "" || req.URL.Scheme == "" && !isConnect) && req.ProtoMajor < 2 ||
		req.Host == "" && req.ProtoMajor == 2 {
		http.Error(wr, BAD_REQ_MSG, http.StatusBadRequest)
		return
	}
	delHopHeaders(req.Header)
	delProxyConnectionTokens(req.Header)
	if isConnect {
		s.HandleTunnel(wr, req)
	} else {
		s.HandleRequest(wr, req)
	}
}

// deadlineRefresher returns a function that pushes the idle deadline of every
// given connection out by idleTimeout. net.Conn methods are safe for
// concurrent use, so both copy directions may call it. It is a no-op when
// idleTimeout is zero.
func deadlineRefresher(idleTimeout time.Duration, conns ...net.Conn) func() {
	if idleTimeout <= 0 {
		return func() {}
	}
	return func() {
		deadline := time.Now().Add(idleTimeout)
		for _, c := range conns {
			_ = c.SetDeadline(deadline)
		}
	}
}

// copyStream copies src to dst until EOF or error, calling refresh after every
// successful read so the caller can extend an idle deadline. It reports
// io.ErrShortWrite when a write is accepted only partially.
func copyStream(dst io.Writer, src io.Reader, refresh func()) (int64, error) {
	buf := make([]byte, COPY_BUF)
	var written int64
	for {
		n, rerr := src.Read(buf)
		if n > 0 {
			refresh()
			w, werr := dst.Write(buf[:n])
			written += int64(w)
			if werr != nil {
				return written, werr
			}
			if w < n {
				return written, io.ErrShortWrite
			}
		}
		if rerr != nil {
			if rerr == io.EOF {
				return written, nil
			}
			return written, rerr
		}
	}
}

func proxy(ctx context.Context, left, right net.Conn, idleTimeout time.Duration) {
	refresh := deadlineRefresher(idleTimeout, left, right)
	wg := sync.WaitGroup{}
	cpy := func(dst, src net.Conn) {
		defer wg.Done()
		copyStream(dst, src, refresh)
		dst.Close()
	}
	wg.Add(2)
	go cpy(left, right)
	go cpy(right, left)
	groupdone := make(chan struct{})
	go func() {
		wg.Wait()
		close(groupdone)
	}()
	select {
	case <-ctx.Done():
		left.Close()
		right.Close()
	case <-groupdone:
		return
	}
	<-groupdone
}

func proxyh2(ctx context.Context, leftreader io.ReadCloser, leftwriter io.Writer, right net.Conn, idleTimeout time.Duration) {
	// leftwriter is the HTTP/2 response writer and has no deadline of its own,
	// so only the upstream socket is refreshed here.
	refresh := deadlineRefresher(idleTimeout, right)
	wg := sync.WaitGroup{}
	ltr := func(dst net.Conn, src io.Reader) {
		defer wg.Done()
		copyStream(dst, src, refresh)
		dst.Close()
	}
	rtl := func(dst io.Writer, src io.Reader) {
		defer wg.Done()
		copyBody(dst, src, refresh)
	}
	wg.Add(2)
	go ltr(right, leftreader)
	go rtl(leftwriter, right)
	groupdone := make(chan struct{}, 1)
	go func() {
		wg.Wait()
		groupdone <- struct{}{}
	}()
	select {
	case <-ctx.Done():
		leftreader.Close()
		right.Close()
	case <-groupdone:
		return
	}
	<-groupdone
}

// Hop-by-hop headers. These are removed when sent to the backend.
// http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html
// "Trailer" is spelled in the singular per RFC 7230 section 6.1; the plural
// form is a historical mistake and http.Header canonicalization never maps
// one onto the other. Proxy-Authorization belongs here too: it authenticates
// the client to *this* proxy and must not leak upstream on a proxy chain.
var hopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Proxy-Connection",
	"Te", // canonicalized version of "TE"
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func delHopHeaders(header http.Header) {
	for _, h := range hopHeaders {
		header.Del(h)
	}
}

// delProxyConnectionTokens removes the headers named in the client's
// Connection header. Those names are hop-by-hop by definition, but they are
// arbitrary and cannot live in the static hopHeaders list.
func delProxyConnectionTokens(header http.Header) {
	for _, v := range header.Values("Connection") {
		for _, tok := range strings.Split(v, ",") {
			name := strings.TrimSpace(tok)
			if name == "" {
				continue
			}
			header.Del(name)
		}
	}
}

// hijack takes over the client connection. The deadline installed by the
// server (ReadHeaderTimeout / ReadTimeout) still applies to the hijacked
// connection, so idleTimeout is used as the per-I/O deadline instead of
// clearing it: a tunnel that goes silent on both ends is eventually reaped
// rather than held open forever. Each direction refreshes the deadline on
// every successful read, so an active tunnel is never interrupted.
func hijack(hijackable interface{}, idleTimeout time.Duration) (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := hijackable.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("connection doesn't support hijacking")
	}
	conn, rw, err := hj.Hijack()
	if err != nil {
		return nil, nil, err
	}
	if idleTimeout > 0 {
		if err := conn.SetDeadline(time.Now().Add(idleTimeout)); err != nil {
			conn.Close()
			return nil, nil, err
		}
	}
	return conn, rw, nil
}

func flush(flusher interface{}) bool {
	f, ok := flusher.(http.Flusher)
	if !ok {
		return false
	}
	f.Flush()
	return true
}

func copyBody(wr io.Writer, body io.Reader, refresh func()) {
	buf := make([]byte, COPY_BUF)
	for {
		bread, read_err := body.Read(buf)
		var write_err error
		if bread > 0 {
			refresh()
			_, write_err = wr.Write(buf[:bread])
			flush(wr)
		}
		if read_err != nil || write_err != nil {
			break
		}
	}
}
