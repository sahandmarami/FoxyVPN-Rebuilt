package main

// HTTP/2 CONNECT tunnel session (port of H2UpstreamSession.kt).
// One TLS+ALPN(h2) connection to the Fastly edge; each user flow becomes an
// HTTP/2 CONNECT stream authenticated with `proxy-authorization: Bearer <pass>`.

import (
        "context"
        "crypto/tls"
        "errors"
        "fmt"
        "io"
        "net"
        "net/http"
        "net/url"
        "strings"
        "sync"
        "sync/atomic"
        "time"

        "golang.org/x/net/http2"
)

const (
        tcpConnectTimeout = 15 * time.Second
        openStreamTimeout = 20 * time.Second
        slotWaitTimeout   = 15 * time.Second
        keepaliveIdle     = 15 * time.Second
        keepalivePingTO   = 25 * time.Second
)

type UpstreamConnectRejected struct {
        StatusCode int
        Authority  string
}

func (e *UpstreamConnectRejected) Error() string {
        return fmt.Sprintf("upstream rejected CONNECT to %s: status=%d", e.Authority, e.StatusCode)
}

type TunnelSession struct {
        host    string
        port    int
        pass    atomic.Value // string
        edgeIP  string
        split   string // "", "first-byte", "sni"

        rawConn net.Conn
        tr      *http2.Transport
        cc      *http2.ClientConn

        mu       sync.Mutex
        closed   bool
        lastUsed atomic.Value // time.Time
}

// DialTunnel establishes the TLS + HTTP/2 connection to the edge.
func DialTunnel(host string, port int, proxyPass, edgeIP, tlsSplit string, dialProxy string) (*TunnelSession, error) {
        if strings.HasPrefix(dialProxy, "socks5://") {
                dialProxy = strings.TrimPrefix(dialProxy, "socks5://")
        }
        if dialProxy != "" && !strings.Contains(dialProxy, ":") {
                dialProxy += ":1080"
        }
        s := &TunnelSession{host: host, port: port, edgeIP: edgeIP, split: tlsSplit}
        s.pass.Store(proxyPass)
        s.lastUsed.Store(time.Now())

        dialAddr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
        if edgeIP != "" && !strings.EqualFold(edgeIP, host) {
                dialAddr = net.JoinHostPort(edgeIP, fmt.Sprintf("%d", port))
        }

        var dialer net.Dialer
        var err error
        if dialProxy != "" {
                s.rawConn, err = dialViaSocks5(dialProxy, host, port)
        } else {
                s.rawConn, err = dialer.DialContext(context.Background(), "tcp", dialAddr)
        }
        if err != nil {
                return nil, fmt.Errorf("TCP connect to %s failed: %w", dialAddr, err)
        }
        if tcp := s.rawConn.(*net.TCPConn); tcp != nil {
                _ = tcp.SetKeepAlive(true)
                _ = tcp.SetKeepAlivePeriod(30 * time.Second)
                _ = tcp.SetNoDelay(true)
        }

        tlsCfg := &tls.Config{
                ServerName: host,
                NextProtos: []string{"h2"},
                MinVersion: tls.VersionTLS12,
        }

        var tlsConn *tls.Conn
        if s.split != "" && dialProxy == "" {
                splitter := &splitConn{Conn: s.rawConn, mode: s.split}
                tlsConn = tls.Client(splitter, tlsCfg)
        } else {
                tlsConn = tls.Client(s.rawConn, tlsCfg)
        }
        hsCtx, cancel := context.WithTimeout(context.Background(), tcpConnectTimeout)
        defer cancel()
        if err := tlsConn.HandshakeContext(hsCtx); err != nil {
                s.rawConn.Close()
                return nil, fmt.Errorf("TLS handshake to %s failed: %w", host, err)
        }
        if proto := tlsConn.ConnectionState().NegotiatedProtocol; proto != "h2" {
                s.rawConn.Close()
                return nil, fmt.Errorf("upstream did not negotiate HTTP/2 over ALPN (got '%s')", proto)
        }

        // Configure H2 flow-control to match the Android app (16 MiB stream window,
        // 256 KiB frames) — a larger receive window keeps throughput high on
        // long-RTT paths. Requires wiring through a net/http.Transport on Go 1.24+.
        t1 := &http.Transport{}
        tr, err := http2.ConfigureTransports(t1)
        if err == nil {
                t1.HTTP2 = &http.HTTP2Config{
                        MaxReceiveBufferPerStream:     16 << 20,
                        MaxReceiveBufferPerConnection: 1 << 30,
                        MaxReadFrameSize:              256 << 10,
                }
                tr.DisableCompression = true
                tr.MaxHeaderListSize = 1 << 20
                tr.ReadIdleTimeout = keepaliveIdle
                tr.PingTimeout = keepalivePingTO
                s.tr = tr
        } else {
                s.tr = &http2.Transport{
                        DisableCompression: true,
                        MaxHeaderListSize:  1 << 20,
                        ReadIdleTimeout:    keepaliveIdle,
                        PingTimeout:        keepalivePingTO,
                }
        }
        cc, err := s.tr.NewClientConn(tlsConn)
        if err != nil {
                s.rawConn.Close()
                return nil, fmt.Errorf("HTTP/2 preface to %s failed: %w", host, err)
        }
        s.cc = cc
        return s, nil
}

// OpenStream opens a CONNECT stream; returns a raw net.Conn-like tunnel.
func (s *TunnelSession) OpenStream(ctx context.Context, targetHost string, targetPort int) (net.Conn, error) {
        if s.cc == nil {
                return nil, errors.New("tunnel session not connected")
        }
        // wait for a free stream slot if the server capped concurrency
        deadline := time.Now().Add(slotWaitTimeout)
        for !s.cc.CanTakeNewRequest() {
                if time.Now().After(deadline) {
                        return nil, errors.New("tunnel has no free stream slot (server limit)")
                }
                if s.IsClosed() {
                        return nil, errors.New("tunnel session is closed")
                }
                time.Sleep(100 * time.Millisecond)
        }

        authority := net.JoinHostPort(targetHost, fmt.Sprintf("%d", targetPort))

        // A chunked, buffered pipe decouples the local writer from the h2 body
        // pump (io.Pipe is synchronous and hurts throughput).
        pipe := newBufPipe()
        req := &http.Request{
                Method: "CONNECT",
                URL:    &url.URL{Host: authority},
                Host:   authority,
                Header: http.Header{
                        "proxy-authorization": {fmt.Sprintf("Bearer %v", s.pass.Load())},
                },
                Body: io.NopCloser(pipe),
        }
        req = req.WithContext(ctx)

        type result struct {
                resp *http.Response
                err  error
        }
        ch := make(chan result, 1)
        go func() {
                resp, err := s.cc.RoundTrip(req)
                ch <- result{resp, err}
        }()

        var resp *http.Response
        select {
        case r := <-ch:
                if r.err != nil {
                        pipe.abortReader(r.err)
                        return nil, classifyRoundTripError(r.err, authority)
                }
                resp = r.resp
        case <-ctx.Done():
                pipe.abortReader(ctx.Err())
                go func() { if r := <-ch; r.resp != nil { r.resp.Body.Close() } }()
                return nil, ctx.Err()
        }

        if resp.StatusCode != 200 {
                pipe.abortReader(errors.New("connect rejected"))
                resp.Body.Close()
                return nil, &UpstreamConnectRejected{StatusCode: resp.StatusCode, Authority: authority}
        }

        s.lastUsed.Store(time.Now())
        tc := &tunnelConn{
                readCloser: resp.Body,
                pipe:       pipe,
                lastUsed:   &s.lastUsed,
        }
        return tc, nil
}

func classifyRoundTripError(err error, authority string) error {
        var goAway http2.GoAwayError
        if errors.As(err, &goAway) || strings.Contains(err.Error(), "GOAWAY") {
                return fmt.Errorf("upstream sent GOAWAY: %w", err)
        }
        if strings.Contains(err.Error(), "connection closed") || strings.Contains(err.Error(), "server closed") {
                return fmt.Errorf("tunnel connection lost: %w", err)
        }
        if strings.Contains(err.Error(), "context deadline exceeded") || strings.Contains(err.Error(), "timeout") {
                return fmt.Errorf("timed out waiting for CONNECT response from edge (%s): %w", authority, err)
        }
        return err
}

func (s *TunnelSession) UpdateBearerToken(token string) {
        if token == "" {
                return
        }
        s.pass.Store(token)
}

func (s *TunnelSession) IsClosed() bool {
        s.mu.Lock()
        defer s.mu.Unlock()
        return s.closed
}

func (s *TunnelSession) Close() {
        s.mu.Lock()
        if s.closed {
                s.mu.Unlock()
                return
        }
        s.closed = true
        s.mu.Unlock()
        if s.cc != nil {
                // best-effort: closing underlying socket tears the session down
        }
        if s.rawConn != nil {
                _ = s.rawConn.Close()
        }
}

// tunnelConn glues resp.Body (downstream) and the buffered pipe (upstream)
// into a single net.Conn for io.Copy relaying.
type tunnelConn struct {
        readCloser io.ReadCloser
        pipe       *bufPipe
        lastUsed   *atomic.Value
        once       sync.Once
}

func (c *tunnelConn) Read(p []byte) (int, error) {
        n, err := c.readCloser.Read(p)
        if n > 0 && c.lastUsed != nil {
                c.lastUsed.Store(time.Now())
        }
        return n, err
}

func (c *tunnelConn) Write(p []byte) (int, error) {
        n, err := c.pipe.Write(p)
        if n > 0 && c.lastUsed != nil {
                c.lastUsed.Store(time.Now())
        }
        return n, err
}

func (c *tunnelConn) Close() error {
        c.once.Do(func() {
                c.pipe.closeWrite()        // EOF -> END_STREAM on request body
                _ = c.readCloser.Close()   // close read side / RST_STREAM
                c.pipe.abortReader(io.EOF) // unblock any stuck writer
        })
        return nil
}

func (c *tunnelConn) LocalAddr() net.Addr                { return nil }
func (c *tunnelConn) RemoteAddr() net.Addr               { return nil }
func (c *tunnelConn) SetDeadline(t time.Time) error      { return nil }
func (c *tunnelConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *tunnelConn) SetWriteDeadline(t time.Time) error { return nil }

// bufPipe is a chunked, buffered, goroutine-safe pipe. Unlike io.Pipe, a
// Write does not block until a matching Read; data buffers up to
// pipeMaxBuffered bytes, keeping the h2 body pump fed with large chunks.
const (
        pipeChunkSize   = 256 * 1024
        pipeMaxBuffered = 8 * 1024 * 1024
)

type bufPipe struct {
        mu       sync.Mutex
        notEmpty *sync.Cond
        notFull  *sync.Cond
        chunks   [][]byte
        cur      []byte
        size     int
        readErr  error // terminal error for the reader side
        writeErr error // terminal error for the writer side
        wClosed  bool
}

func newBufPipe() *bufPipe {
        p := &bufPipe{cur: make([]byte, 0, pipeChunkSize)}
        p.notEmpty = sync.NewCond(&p.mu)
        p.notFull = sync.NewCond(&p.mu)
        return p
}

func (p *bufPipe) writeErrOrEOF() error {
        if p.writeErr != nil {
                return p.writeErr
        }
        return io.ErrClosedPipe
}

func (p *bufPipe) Write(b []byte) (int, error) {
        p.mu.Lock()
        defer p.mu.Unlock()
        if p.writeErr != nil || p.wClosed {
                return 0, p.writeErrOrEOF()
        }
        total := 0
        for len(b) > 0 {
                for p.size >= pipeMaxBuffered && p.readErr == nil {
                        p.notFull.Wait()
                }
                if p.readErr != nil {
                        return total, p.readErr
                }
                if p.writeErr != nil || p.wClosed {
                        return total, p.writeErrOrEOF()
                }
                space := pipeChunkSize - len(p.cur)
                n := len(b)
                if n > space {
                        n = space
                }
                p.cur = append(p.cur, b[:n]...)
                b = b[n:]
                total += n
                p.size += n
                if len(p.cur) == pipeChunkSize {
                        p.chunks = append(p.chunks, p.cur)
                        p.cur = make([]byte, 0, pipeChunkSize)
                }
                p.notEmpty.Signal()
        }
        return total, nil
}

func (p *bufPipe) Read(dst []byte) (int, error) {
        p.mu.Lock()
        defer p.mu.Unlock()
        for {
                if len(p.chunks) > 0 {
                        chunk := p.chunks[0]
                        n := copy(dst, chunk)
                        if n == len(chunk) {
                                p.chunks = p.chunks[1:]
                        } else {
                                p.chunks[0] = chunk[n:]
                        }
                        p.size -= n
                        p.notFull.Signal()
                        return n, nil
                }
                if len(p.cur) > 0 {
                        n := copy(dst, p.cur)
                        p.cur = p.cur[n:]
                        p.size -= n
                        p.notFull.Signal()
                        return n, nil
                }
                if p.readErr != nil {
                        return 0, p.readErr
                }
                if p.wClosed {
                        return 0, io.EOF
                }
                p.notEmpty.Wait()
        }
}

// closeWrite signals EOF to the reader (END_STREAM path).
func (p *bufPipe) closeWrite() {
        p.mu.Lock()
        p.wClosed = true
        p.mu.Unlock()
        p.notEmpty.Broadcast()
        p.notFull.Broadcast()
}

// abortReader terminates both sides with err (tunnel death / teardown).
func (p *bufPipe) abortReader(err error) {
        if err == nil {
                err = io.EOF
        }
        p.mu.Lock()
        if p.readErr == nil {
                p.readErr = err
        }
        p.mu.Unlock()
        p.notEmpty.Broadcast()
        p.notFull.Broadcast()
}

// dialViaSocks5 connects through a user-supplied upstream SOCKS5 proxy.
func dialViaSocks5(proxyAddr, host string, port int) (net.Conn, error) {
        d := net.Dialer{Timeout: tcpConnectTimeout}
        conn, err := d.Dial("tcp", proxyAddr)
        if err != nil {
                return nil, err
        }
        // greeting: no auth
        if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
                conn.Close()
                return nil, err
        }
        buf := make([]byte, 2)
        if _, err := io.ReadFull(conn, buf); err != nil || buf[0] != 5 || buf[1] != 0 {
                conn.Close()
                return nil, errors.New("upstream proxy greeting failed")
        }
        hostBytes := []byte(host)
        req := []byte{5, 1, 0, 3, byte(len(hostBytes))}
        req = append(req, hostBytes...)
        var portBytes [2]byte
        binaryBigEndianPutUint16(portBytes[:], uint16(port))
        req = append(req, portBytes[:]...)
        if _, err := conn.Write(req); err != nil {
                conn.Close()
                return nil, err
        }
        resp := make([]byte, 4)
        if _, err := io.ReadFull(conn, resp); err != nil || resp[1] != 0 {
                conn.Close()
                return nil, errors.New("upstream proxy CONNECT failed")
        }
        switch resp[3] {
        case 1:
                rest := make([]byte, 6)
                if _, err := io.ReadFull(conn, rest); err != nil {
                        conn.Close()
                        return nil, err
                }
        case 3:
                l := make([]byte, 1)
                if _, err := io.ReadFull(conn, l); err != nil {
                        conn.Close()
                        return nil, err
                }
                rest := make([]byte, int(l[0])+2)
                if _, err := io.ReadFull(conn, rest); err != nil {
                        conn.Close()
                        return nil, err
                }
        case 4:
                rest := make([]byte, 18)
                if _, err := io.ReadFull(conn, rest); err != nil {
                        conn.Close()
                        return nil, err
                }
        }
        return conn, nil
}

func binaryBigEndianPutUint16(b []byte, v uint16) {
        b[0] = byte(v >> 8)
        b[1] = byte(v)
}

