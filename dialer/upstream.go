package dialer

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

const (
	PROXY_CONNECT_METHOD       = "CONNECT"
	PROXY_HOST_HEADER          = "Host"
	PROXY_AUTHORIZATION_HEADER = "Proxy-Authorization"

	// MAX_PROXY_RESPONSE_HEADER bounds the upstream proxy reply header block.
	MAX_PROXY_RESPONSE_HEADER = 64 * 1024
	// maxProxyResponseLine bounds a single header line, and thus the read buffer.
	maxProxyResponseLine = 8 * 1024
)

type stringCb = func() (string, error)

type Dialer interface {
	Dial(network, address string) (net.Conn, error)
}

type ContextDialer interface {
	Dialer
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

type ProxyDialer struct {
	address       stringCb
	tlsServerName stringCb
	fakeSNI       stringCb
	auth          stringCb
	next          ContextDialer
	caPool        *x509.CertPool
	timeout       time.Duration
}

func NewProxyDialer(address, tlsServerName, fakeSNI, auth stringCb, caPool *x509.CertPool, nextDialer ContextDialer, timeout time.Duration) *ProxyDialer {
	return &ProxyDialer{
		address:       address,
		tlsServerName: tlsServerName,
		fakeSNI:       fakeSNI,
		auth:          auth,
		next:          nextDialer,
		caPool:        caPool,
		timeout:       timeout,
	}
}

func ProxyDialerFromURL(u *url.URL, next ContextDialer) (*ProxyDialer, error) {
	host := u.Hostname()
	port := u.Port()
	tlsServerName := ""
	var auth stringCb = nil

	switch strings.ToLower(u.Scheme) {
	case "http":
		if port == "" {
			port = "80"
		}
	case "https":
		if port == "" {
			port = "443"
		}
		tlsServerName = host
	default:
		return nil, errors.New("unsupported proxy type")
	}

	address := net.JoinHostPort(host, port)

	if u.User != nil {
		username := u.User.Username()
		password, _ := u.User.Password()
		auth = WrapStringToCb(BasicAuthHeader(username, password))
	}
	return NewProxyDialer(
		WrapStringToCb(address),
		WrapStringToCb(tlsServerName),
		WrapStringToCb(tlsServerName),
		auth,
		nil,
		next,
		0), nil
}

func (d *ProxyDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, errors.New("bad network specified for DialContext: only tcp is supported")
	}

	uAddress, err := d.address()
	if err != nil {
		return nil, err
	}
	conn, err := d.next.DialContext(ctx, "tcp", uAddress)
	if err != nil {
		return nil, err
	}

	uTLSServerName, err := d.tlsServerName()
	if err != nil {
		return nil, err
	}
	fakeSNI, err := d.fakeSNI()
	if err != nil {
		return nil, err
	}
	// Wait for the whole exchange to fit inside the configured timeout. The
	// deadline covers the CONNECT response and is lifted before returning, so
	// the tunnel the caller gets back is not left with a stale deadline.
	if d.timeout > 0 {
		if err := conn.SetDeadline(time.Now().Add(d.timeout)); err != nil {
			conn.Close()
			return nil, err
		}
		defer conn.SetDeadline(time.Time{})
	}

	if uTLSServerName != "" {
		// Custom cert verification logic:
		// DO NOT send SNI extension of TLS ClientHello
		// DO peer certificate verification against specified servername
		conn = tls.Client(conn, &tls.Config{
			ServerName:         fakeSNI,
			InsecureSkipVerify: true,
			VerifyConnection: func(cs tls.ConnectionState) error {
				opts := x509.VerifyOptions{
					DNSName:       uTLSServerName,
					Intermediates: x509.NewCertPool(),
					Roots:         d.caPool,
				}
				for _, cert := range cs.PeerCertificates[1:] {
					opts.Intermediates.AddCert(cert)
				}
				_, err := cs.PeerCertificates[0].Verify(opts)
				return err
			},
		})
	}

	req := &http.Request{
		Method:     PROXY_CONNECT_METHOD,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		RequestURI: address,
		Host:       address,
		Header: http.Header{
			PROXY_HOST_HEADER: []string{address},
		},
	}

	if d.auth != nil {
		auth, err := d.auth()
		if err != nil {
			return nil, err
		}
		req.Header.Set(PROXY_AUTHORIZATION_HEADER, auth)
	}

	rawreq, err := httputil.DumpRequest(req, false)
	if err != nil {
		return nil, err
	}

	_, err = conn.Write(rawreq)
	if err != nil {
		return nil, err
	}

	proxyResp, err := readResponse(conn, req)
	if err != nil {
		return nil, err
	}

	if proxyResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad response from upstream proxy server: %s", proxyResp.Status)
	}

	return conn, nil
}

func (d *ProxyDialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

func (d *ProxyDialer) Address() (string, error) {
	return d.address()
}

// readResponse reads the status line and headers of the upstream proxy reply.
// It is capped at MAX_PROXY_RESPONSE_HEADER bytes so a malicious or broken
// upstream cannot drive unbounded allocation, and reports a distinct error
// when the cap is hit so the caller can tell that apart from a short reply.
func readResponse(r io.Reader, req *http.Request) (*http.Response, error) {
	br := bufio.NewReaderSize(r, maxProxyResponseLine)
	header := make([]byte, 0, 512)
	for {
		line, err := br.ReadSlice('\n')
		header = append(header, line...)
		// bufio.ErrBufferFull means a single line exceeded the read buffer,
		// which is itself a too-large header.
		if err == bufio.ErrBufferFull || len(header) > MAX_PROXY_RESPONSE_HEADER {
			return nil, errors.New("upstream proxy response header too large")
		}
		if err != nil {
			return nil, fmt.Errorf("reading upstream proxy response: %w", err)
		}
		// End of header block: an empty line, i.e. CRLF or bare LF.
		trimmed := bytes.TrimRight(line, "\r\n")
		if len(trimmed) == 0 {
			break
		}
	}
	return http.ReadResponse(bufio.NewReader(bytes.NewReader(header)), req)
}

func BasicAuthHeader(login, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString(
		[]byte(login+":"+password))
}

func WrapStringToCb(s string) func() (string, error) {
	return func() (string, error) {
		return s, nil
	}
}
