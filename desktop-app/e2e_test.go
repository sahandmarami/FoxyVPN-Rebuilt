package main

// End-to-end mock test: a real HTTP/2 CONNECT server (TLS) plays the Fastly
// edge, then we exercise DialTunnel -> probeTunnel -> LocalProxy (HTTP,
// CONNECT and SOCKS5) exactly as the app would in the field.

import (
        "bufio"
        "crypto/rand"
        "crypto/rsa"
        "crypto/tls"
        "crypto/x509"
        "crypto/x509/pkix"
        "encoding/pem"
        "fmt"
        "io"
        "math/big"
        "net"
        "net/http"
        "net/url"
        "os"
        "path/filepath"
        "strings"
        "testing"
        "time"

        "golang.org/x/net/http2"
)

func genTestCerts(t *testing.T) (leafPath, caPath string) {
        t.Helper()
        dir := t.TempDir()

        caKey, err := rsa.GenerateKey(rand.Reader, 2048)
        if err != nil {
                t.Fatal(err)
        }
        caTmpl := &x509.Certificate{
                SerialNumber:          big.NewInt(1),
                Subject:               pkix.Name{CommonName: "foxyvpn-test-ca"},
                NotBefore:             time.Now().Add(-time.Hour),
                NotAfter:              time.Now().Add(24 * time.Hour),
                IsCA:                  true,
                KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
                BasicConstraintsValid: true,
        }
        caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
        if err != nil {
                t.Fatal(err)
        }
        caCert, err := x509.ParseCertificate(caDER)
        if err != nil {
                t.Fatal(err)
        }

        leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
        if err != nil {
                t.Fatal(err)
        }
        leafTmpl := &x509.Certificate{
                SerialNumber: big.NewInt(2),
                Subject:      pkix.Name{CommonName: "localhost"},
                NotBefore:    time.Now().Add(-time.Hour),
                NotAfter:     time.Now().Add(24 * time.Hour),
                DNSNames:     []string{"localhost"},
                IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
                KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
                ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
        }
        leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
        if err != nil {
                t.Fatal(err)
        }

        leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
        caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
        keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(leafKey)})

        leafPath = filepath.Join(dir, "leaf.pem")
        caPath = filepath.Join(dir, "ca.pem")
        if err := os.WriteFile(leafPath, append(append(leafPEM, caPEM...), keyPEM...), 0o600); err != nil {
                t.Fatal(err)
        }
        if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
                t.Fatal(err)
        }
        return leafPath, caPath
}

func startMockEdge(t *testing.T) (addr, caPath string) {
        t.Helper()
        leafPath, caPath := genTestCerts(t)
        cert, err := tls.LoadX509KeyPair(leafPath, leafPath)
        if err != nil {
                t.Fatal(err)
        }
        ln, err := net.Listen("tcp", "127.0.0.1:0")
        if err != nil {
                t.Fatal(err)
        }
        t.Cleanup(func() { ln.Close() })

        h2s := &http2.Server{}
        handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                if r.Method != "CONNECT" {
                        w.WriteHeader(http.StatusMethodNotAllowed)
                        return
                }
                w.WriteHeader(http.StatusOK) // 200 Connection Established
                if f, ok := w.(http.Flusher); ok {
                        f.Flush()
                }
                // first bytes from the client = their tunneled request; answer 204
                buf := make([]byte, 4096)
                n, rerr := r.Body.Read(buf)
                if n > 0 {
                        w.Write([]byte("HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"))
                        if f, ok := w.(http.Flusher); ok {
                                f.Flush()
                        }
                }
                if rerr == nil {
                        _, _ = io.Copy(io.Discard, r.Body)
                }
        })
        go func() {
                for {
                        conn, aerr := ln.Accept()
                        if aerr != nil {
                                return
                        }
                        go func() {
                                tc := tls.Server(conn, &tls.Config{
                                        Certificates: []tls.Certificate{cert},
                                        NextProtos:   []string{"h2"},
                                })
                                if herr := tc.Handshake(); herr != nil {
                                        t.Logf("mock edge: server handshake error: %v", herr)
                                        return
                                }
                                cs := tc.ConnectionState()
                                t.Logf("mock edge: server version=0x%04x alpn=%q cipher=0x%04x", cs.Version, cs.NegotiatedProtocol, cs.CipherSuite)
                                h2s.ServeConn(tc, &http2.ServeConnOpts{Handler: handler})
                        }()
                }
        }()
        return ln.Addr().String(), caPath
}

func TestE2EMock(t *testing.T) {
        edgeAddr, caPath := startMockEdge(t)
        _, portStr, _ := net.SplitHostPort(edgeAddr)
        var port int
        fmt.Sscanf(portStr, "%d", &port)

        // trust the mock CA through the pinned test pool (SSL_CERT_FILE is
        // unreliable here because Go caches the system pool per process)
        caPEM, err := os.ReadFile(caPath)
        if err != nil {
                t.Fatal(err)
        }
        pool := x509.NewCertPool()
        pool.AppendCertsFromPEM(caPEM)
        testRootCAs = pool
        defer func() { testRootCAs = nil }()

        sess, err := DialTunnel("localhost", port, "test-pass-token", "", "", "")
        if err != nil {
                t.Fatalf("DialTunnel: %v", err)
        }
        defer sess.Close()

        // 1) probeTunnel must pass against the mock (traffic really flows)
        if err := probeTunnel(sess, NewDohResolver()); err != nil {
                t.Fatalf("probeTunnel: %v", err)
        }
        t.Logf("probeTunnel OK")

        // 2) local HTTP proxy (plain GET via absolute URI)
        resolver := NewDohResolver()
        counters := &Counters{}
        p := NewLocalProxy("127.0.0.1", 0, 0, resolver, counters)
        p.SetSession(func() (streamOpener, bool) { return sess, true })
        // pick free ports manually since Start() walks upward from the given one
        for i := 0; i < 50 && p.socksLn == nil; i++ {
                p.socksPort = 20000 + i*7
                p.httpPort = 20001 + i*7
                if err := p.Start(); err != nil {
                        t.Fatalf("LocalProxy.Start: %v", err)
                }
        }
        defer p.Stop()

        client := &http.Client{
                Timeout: 15 * time.Second,
                Transport: &http.Transport{
                        Proxy: func(*http.Request) (*url.URL, error) {
                                return url.Parse(fmt.Sprintf("http://127.0.0.1:%d", p.HttpPort()))
                        },
                },
        }
        resp, err := client.Get("http://mock-target.test/generate_204")
        if err != nil {
                t.Fatalf("via HTTP proxy: %v", err)
        }
        resp.Body.Close()
        if resp.StatusCode != 204 {
                t.Fatalf("via HTTP proxy: got %d, want 204", resp.StatusCode)
        }
        t.Logf("HTTP proxy plain GET OK (counters up=%d down=%d)", counters.Up.Load(), counters.Down.Load())

        // 3) HTTP proxy CONNECT (what browsers do for https)
        raw, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", p.HttpPort()))
        if err != nil {
                t.Fatal(err)
        }
        defer raw.Close()
        fmt.Fprintf(raw, "CONNECT some.host.test:443 HTTP/1.1\r\nHost: some.host.test:443\r\n\r\n")
        br := bufio.NewReader(raw)
        status, err := br.ReadString('\n')
        if err != nil {
                t.Fatalf("CONNECT read: %v", err)
        }
        if !strings.Contains(status, "200") {
                t.Fatalf("CONNECT rejected: %q", status)
        }
        // drain the rest of the CONNECT response headers
        for {
                hl, herr := br.ReadString('\n')
                if herr != nil {
                        t.Fatalf("CONNECT header read: %v", herr)
                }
                if hl == "\r\n" || hl == "\n" {
                        break
                }
        }
        fmt.Fprintf(raw, "GET /generate_204 HTTP/1.1\r\nHost: some.host.test\r\n\r\n")
        line2, err := br.ReadString('\n')
        if err != nil {
                t.Fatalf("tunneled GET read: %v", err)
        }
        if !strings.Contains(line2, "204") {
                t.Fatalf("tunneled GET got %q", line2)
        }
        t.Logf("HTTP proxy CONNECT OK")
        raw.Close()

        // 4) SOCKS5
        sraw, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", p.SocksPort()))
        if err != nil {
                t.Fatal(err)
        }
        defer sraw.Close()
        sbr := bufio.NewReader(sraw)
        sraw.Write([]byte{5, 1, 0})
        greet := make([]byte, 2)
        if _, err := io.ReadFull(sbr, greet); err != nil || greet[0] != 5 || greet[1] != 0 {
                t.Fatalf("socks greeting failed: %v %v", greet, err)
        }
        req := []byte{5, 1, 0, 3, 14}
        req = append(req, []byte("some.host.test")...)
        req = append(req, 0, 80)
        sraw.Write(req)
        srep := make([]byte, 4)
        if _, err := io.ReadFull(sbr, srep); err != nil || srep[1] != 0 {
                t.Fatalf("socks connect failed: %v %v", srep, err)
        }
        rest := make([]byte, 6)
        if _, err := io.ReadFull(sbr, rest); err != nil {
                t.Fatal(err)
        }
        sraw.Write([]byte("GET /generate_204 HTTP/1.1\r\nHost: some.host.test\r\n\r\n"))
        sline, err := sbr.ReadString('\n')
        if err != nil {
                t.Fatalf("socks tunneled read: %v", err)
        }
        if !strings.Contains(sline, "204") {
                t.Fatalf("socks tunneled got %q", sline)
        }
        t.Logf("SOCKS5 OK")
}
