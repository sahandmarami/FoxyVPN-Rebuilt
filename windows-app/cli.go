package main

// CLI subcommands for smoke-testing protocol pieces without the GUI.

import (
        "context"
        "fmt"
        "os"
        "strings"
        "time"
)

func mustCtx(d time.Duration) context.Context {
        ctx, cancel := context.WithTimeout(context.Background(), d)
        _ = cancel
        return ctx
}

func runCLI(args []string) {
        initControlPlane()
        challengeSolveFunc = solveFastlyChallenge
        cmd := args[0]

        switch cmd {
        case "servers":
                sl := NewServerList("")
                countries, err := sl.Refresh(true)
                if err != nil {
                        fmt.Fprintln(os.Stderr, "error:", err)
                        os.Exit(1)
                }
                total := 0
                for _, c := range countries {
                        n := 0
                        for _, city := range c.Cities {
                                n += len(city.Servers)
                        }
                        total += n
                        fmt.Printf("%-4s %-30s %d city(ies), %d server(s)\n", c.Code, c.Name, len(c.Cities), n)
                }
                fmt.Printf("total: %d countries, %d servers\n", len(countries), total)

        case "doh":
                if len(args) < 2 {
                        fmt.Println("usage: doh <hostname>")
                        return
                }
                r := NewDohResolver()
                ip, ok := r.Resolve(args[1])
                fmt.Printf("%s -> %s (ok=%v)\n", args[1], ip, ok)

        case "test-tunnel":
                host, port := "faor73.m1.fastly-masque.net", 2499
                if len(args) > 1 {
                        if h, p, ok := strings.Cut(args[1], ":"); ok {
                                host = h
                                fmt.Sscanf(p, "%d", &port)
                        }
                }
                r := NewDohResolver()
                ip, _ := r.EdgeAddress(host)
                fmt.Printf("edge %s => IP %s\n", host, ip)
                sess, err := DialTunnel(host, port, "fake-token-for-reachability-test", ip, "sni", "")
                if err != nil {
                        fmt.Println("DIAL FAILED:", err)
                        os.Exit(1)
                }
                defer sess.Close()
                fmt.Println("TLS+ALPN(h2)+HTTP/2 preface OK — opening test CONNECT stream…")
                conn, err := sess.OpenStream(mustCtx(10*time.Second), "www.cloudflare.com", 443)
                if err != nil {
                        fmt.Printf("CONNECT answered: %v\n", err)
                        if _, ok := err.(*UpstreamConnectRejected); ok {
                                fmt.Println("(expected with a fake token — the tunnel protocol works end-to-end)")
                                return
                        }
                        os.Exit(1)
                }
                _ = conn
                fmt.Println("CONNECT unexpectedly succeeded with a fake token?!")
                os.Exit(2)

        case "test-fxa":
                email := "nonexistent-foxyvpn-test@example.com"
                if len(args) > 1 {
                        email = args[1]
                }
                fxa := FxaClient{}
                _, _, _, err := fxa.login(email, "definitely-not-the-password-123456")
                if err != nil {
                        if apiErr, ok := err.(*FxaApiError); ok {
                                fmt.Printf("FxA reachable — answered errno=%d status=%d: %s\n", apiErr.Errno, apiErr.StatusCode, apiErr.Message)
                                return
                        }
                        fmt.Println("transport error:", err)
                        os.Exit(1)
                }
                fmt.Println("unexpected success with bogus credentials?!")

        default:
                fmt.Println("unknown subcommand:", cmd)
                fmt.Println("available: servers | doh <host> | test-tunnel [host:port] | test-fxa <email>")
        }
}
