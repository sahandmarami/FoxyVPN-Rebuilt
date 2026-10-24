package main

// Local SOCKS5 + HTTP proxy servers that route flows through the tunnel.

import (
        "bufio"
        "context"
        "errors"
        "fmt"
        "io"
        "net"
        "strconv"
        "strings"
        "sync"
        "sync/atomic"
        "time"
)

type Counters struct {
        Up   atomic.Int64
        Down atomic.Int64
}

type LocalProxy struct {
        mu        sync.Mutex
        socksLn   net.Listener
        httpLn    net.Listener
        socksPort int
        httpPort  int
        bind      string
        session   func() (streamOpener, bool) // current upstream accessor
        resolver  *DohResolver
        counters  *Counters
        wg        sync.WaitGroup
        conns     map[net.Conn]struct{} // live client conns (closed on Stop)
}

// streamOpener abstracts TunnelSession for the proxies.
type streamOpener interface {
        OpenStream(ctx context.Context, host string, port int) (net.Conn, error)
}

func NewLocalProxy(bind string, socksPort, httpPort int, resolver *DohResolver, counters *Counters) *LocalProxy {
        return &LocalProxy{bind: bind, socksPort: socksPort, httpPort: httpPort, resolver: resolver, counters: counters, conns: map[net.Conn]struct{}{}}
}

func (p *LocalProxy) SetSession(opener func() (streamOpener, bool)) {
        p.mu.Lock()
        p.session = opener
        p.mu.Unlock()
}

func (p *LocalProxy) opener() (streamOpener, bool) {
        p.mu.Lock()
        defer p.mu.Unlock()
        if p.session == nil {
                return nil, false
        }
        return p.session()
}

func (p *LocalProxy) SocksPort() int { return p.socksPort }
func (p *LocalProxy) HttpPort() int  { return p.httpPort }

// Start binds both listeners, walking ports forward if busy. Returns actual ports.
func (p *LocalProxy) Start() error {
        for i := 0; i < 20; i++ {
                addr := net.JoinHostPort(p.bind, strconv.Itoa(p.socksPort))
                ln, lerr := net.Listen("tcp", addr)
                if lerr == nil {
                        p.socksLn = ln
                        break
                }
                if !isAddrInUse(lerr) {
                        return fmt.Errorf("cannot bind SOCKS listener: %w", lerr)
                }
                p.socksPort++
        }
        if p.socksLn == nil {
                return errors.New("no free port for SOCKS listener")
        }
        for i := 0; i < 20; i++ {
                addr := net.JoinHostPort(p.bind, strconv.Itoa(p.httpPort))
                ln, lerr := net.Listen("tcp", addr)
                if lerr == nil {
                        p.httpLn = ln
                        break
                }
                p.httpPort++
        }
        if p.httpLn == nil {
                p.socksLn.Close()
                return errors.New("no free port for HTTP listener")
        }
        go p.acceptLoop(p.socksLn, p.serveSocks)
        go p.acceptLoop(p.httpLn, p.serveHTTP)
        return nil
}

func (p *LocalProxy) acceptLoop(ln net.Listener, handler func(net.Conn)) {
        for {
                conn, err := ln.Accept()
                if err != nil {
                        return
                }
                p.trackConn(conn, true)
                p.wg.Add(1)
                go func() {
                        defer p.wg.Done()
                        defer p.trackConn(conn, false)
                        handler(conn)
                }()
        }
}

func (p *LocalProxy) trackConn(conn net.Conn, add bool) {
        p.mu.Lock()
        defer p.mu.Unlock()
        if p.conns == nil {
                p.conns = map[net.Conn]struct{}{}
        }
        if add {
                p.conns[conn] = struct{}{}
        } else {
                delete(p.conns, conn)
        }
}

func (p *LocalProxy) Stop() {
        if p.socksLn != nil {
                p.socksLn.Close()
        }
        if p.httpLn != nil {
                p.httpLn.Close()
        }
        // force-close live client conns so waiting flows end immediately
        p.mu.Lock()
        for conn := range p.conns {
                conn.Close()
        }
        p.conns = map[net.Conn]struct{}{}
        p.mu.Unlock()
        p.wg.Wait()
}

func isAddrInUse(err error) bool {
        return strings.Contains(err.Error(), "in use") || strings.Contains(err.Error(), "address already")
}

// ---------- SOCKS5 ----------

func (p *LocalProxy) serveSocks(conn net.Conn) {
        defer conn.Close()
        _ = conn.SetDeadline(time.Now().Add(30 * time.Second))
        br := bufio.NewReader(conn)

        head := make([]byte, 2)
        if _, err := io.ReadFull(br, head); err != nil || head[0] != 5 {
                return
        }
        methods := make([]byte, int(head[1]))
        if _, err := io.ReadFull(br, methods); err != nil {
                return
        }
        if _, err := conn.Write([]byte{5, 0}); err != nil { // no-auth
                return
        }
        _ = conn.SetDeadline(time.Time{})

        req := make([]byte, 4)
        if _, err := io.ReadFull(br, req); err != nil || req[0] != 5 || req[1] != 1 {
                return
        }
        var host string
        var port int
        switch req[3] {
        case 1: // IPv4
                b := make([]byte, 6)
                if _, err := io.ReadFull(br, b); err != nil {
                        return
                }
                host = net.IP(b[:4]).String()
                port = int(b[4])<<8 | int(b[5])
        case 3: // domain
                l := make([]byte, 1)
                if _, err := io.ReadFull(br, l); err != nil {
                        return
                }
                b := make([]byte, int(l[0])+2)
                if _, err := io.ReadFull(br, b); err != nil {
                        return
                }
                host = string(b[:len(b)-2])
                port = int(b[len(b)-2])<<8 | int(b[len(b)-1])
        case 4: // IPv6
                b := make([]byte, 18)
                if _, err := io.ReadFull(br, b); err != nil {
                        return
                }
                host = net.IP(b[:16]).String()
                port = int(b[16])<<8 | int(b[17])
        default:
                conn.Write([]byte{5, 8, 0, 1, 0, 0, 0, 0})
                return
        }
        _ = br // any leftover bytes (rare for socks) are ignored

        up, err := p.openTunnelConn(host, port)
        if err != nil {
                code := byte(1)
                if errors.Is(err, errNotConnected) {
                        code = 1
                }
                conn.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0}) // VER REP RSV ATYP BND.ADDR(4) BND.PORT(2)
                return
        }
        conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
        relay(conn, up, p.counters)
}

// ---------- HTTP proxy ----------

func (p *LocalProxy) serveHTTP(conn net.Conn) {
        defer conn.Close()
        _ = conn.SetDeadline(time.Now().Add(30 * time.Second))
        br := bufio.NewReader(conn)

        reqLine, err := readLine(br)
        if err != nil {
                return
        }
        parts := strings.Fields(reqLine)
        if len(parts) < 3 {
                return
        }
        method, target := parts[0], parts[1]

        // read + forward headers
        var headers []string
        contentLen := 0
        for {
                line, err := readLine(br)
                if err != nil {
                        return
                }
                if line == "" {
                        break
                }
                headers = append(headers, line)
                lower := strings.ToLower(line)
                if strings.HasPrefix(lower, "content-length:") {
                        if v, verr := strconv.Atoi(strings.TrimSpace(line[15:])); verr == nil {
                                contentLen = v
                        }
                }
        }
        _ = conn.SetDeadline(time.Time{})

        if strings.EqualFold(method, "CONNECT") {
                authority := target
                host, port, ok := splitAuthority(authority)
                if !ok {
                        conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
                        return
                }
                up, terr := p.openTunnelConn(host, port)
                if terr != nil {
                        conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
                        return
                }
                conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
                relay(conn, up, p.counters)
                return
        }

        // plain HTTP: extract host/port from absolute URI, forward raw bytes
        host, port, ok := parseAbsoluteTarget(target)
        if !ok {
                conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
                return
        }
        up, terr := p.openTunnelConn(host, port)
        if terr != nil {
                conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
                return
        }
        // rewrite request line to origin-form
        path := target
        if idx := strings.Index(target, "://"); idx >= 0 {
                rest := target[idx+3:]
                if slash := strings.Index(rest, "/"); slash >= 0 {
                        path = rest[slash:]
                } else {
                        path = "/"
                }
        }
        var sb strings.Builder
        sb.WriteString(method + " " + path + " " + parts[2] + "\r\n")
        for _, h := range headers {
                lower := strings.ToLower(h)
                if strings.HasPrefix(lower, "proxy-") || strings.HasPrefix(lower, "proxy-authorization") {
                        continue
                }
                sb.WriteString(h + "\r\n")
        }
        sb.WriteString("\r\n")
        if _, err := up.Write([]byte(sb.String())); err != nil {
                up.Close()
                return
        }
        // body if any
        if contentLen > 0 {
                if _, err := io.CopyN(up, br, int64(contentLen)); err != nil {
                        up.Close()
                        return
                }
        }
        relay(conn, up, p.counters)
}

func readLine(br *bufio.Reader) (string, error) {
        line, err := br.ReadString('\n')
        if err != nil {
                return "", err
        }
        return strings.TrimRight(line, "\r\n"), nil
}

func splitAuthority(authority string) (string, int, bool) {
        host, portStr, err := net.SplitHostPort(authority)
        if err != nil {
                return "", 0, false
        }
        port, err := strconv.Atoi(portStr)
        if err != nil || port <= 0 || port > 65535 {
                return "", 0, false
        }
        return host, port, true
}

func parseAbsoluteTarget(target string) (string, int, bool) {
        idx := strings.Index(target, "://")
        scheme := "http"
        rest := target
        if idx >= 0 {
                scheme = target[:idx]
                rest = target[idx+3:]
        }
        if scheme != "http" {
                return "", 0, false
        }
        host := rest
        port := 80
        if slash := strings.Index(rest, "/"); slash >= 0 {
                host = rest[:slash]
        }
        if h, p, ok := splitAuthority(host); ok {
                host, port = h, p
        } else if strings.Contains(host, ":") {
                return "", 0, false
        }
        return host, port, true
}

// ---------- shared plumbing ----------

var errNotConnected = errors.New("VPN is not connected")

type cancelConn struct {
        net.Conn
        cancel context.CancelFunc
}

func (c *cancelConn) Close() error {
        c.cancel()
        return c.Conn.Close()
}

func (p *LocalProxy) openTunnelConn(host string, port int) (net.Conn, error) {
        op, ok := p.opener()
        if !ok {
                return nil, errNotConnected
        }
        // resolve hostnames via DoH so a poisoned local resolver can't break flows
        dialHost := host
        if net.ParseIP(host) == nil {
                if ip, ok2 := p.resolver.Resolve(host); ok2 {
                        dialHost = ip
                }
        }
        ctx, cancel := context.WithTimeout(context.Background(), openStreamTimeout)
        up, err := op.OpenStream(ctx, dialHost, port)
        if err != nil {
                cancel()
                return nil, err
        }
        return &cancelConn{Conn: up, cancel: cancel}, nil
}

func relay(a, b net.Conn, counters *Counters) {
        done := make(chan struct{}, 2)
        cp := func(dst io.Writer, src io.Reader, dir string) {
                buf := make([]byte, 64*1024)
                for {
                        n, rerr := src.Read(buf)
                        if n > 0 {
                                if counters != nil {
                                        if dir == "up" {
                                                counters.Up.Add(int64(n))
                                        } else {
                                                counters.Down.Add(int64(n))
                                        }
                                }
                                if _, werr := dst.Write(buf[:n]); werr != nil {
                                        break
                                }
                        }
                        if rerr != nil {
                                break
                        }
                }
                if tc, ok := dst.(net.Conn); ok {
                        _ = tc.SetReadDeadline(time.Now())
                }
                done <- struct{}{}
        }
        go cp(b, a, "up")
        go cp(a, b, "down")
        <-done
        a.Close()
        b.Close()
        <-done
}
