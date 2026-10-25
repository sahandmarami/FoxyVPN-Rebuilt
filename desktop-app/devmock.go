//go:build devmock

package main

// Dev-only mock API server (build with:  go build -tags devmock) that serves
// the embedded UI with canned responses so the interface can be verified in
// a browser without a Windows machine. Never part of the shipped app.

import (
        "encoding/json"
        "fmt"
        "net/http"
        "time"
)

func init() { devMockHook = runMockServer }

func runMockServer(port int) {
        state := map[string]any{
                "state":        "connected",
                "connected":    true,
                "since":        time.Now().Add(-3720 * time.Second).UTC().Format(time.RFC3339),
                "exit_ip":      "94.251.188.123",
                "exit_country": "BE",
                "has_key":      true,
                "key": map[string]any{
                        "name": "ساحند", "code": "3184257690", "key_id": "a91f34cd",
                        "gb": 50, "mb": 0, "expires_at": 0,
                },
                "used_bytes":   16_900_000_000.0,
                "limit_bytes":  50_000_000_000.0,
                "reset_at":     time.Now().Add(11 * 24 * time.Hour).Unix(),
                "sync_ok_at":   time.Now().UnixMilli(),
                "up_bytes":     182_400_000,
                "down_bytes":   1_842_000_000,
                "country":      "BE",
                "city":         "",
                "sys_proxy":    true,
                "auto_connect": true,
                "socks_port":   1080,
                "http_port":    8080,
                "ui_port":      port,
                "tls_split":    "sni",
                "version":      "1.1.0",
        }
        servers := map[string]any{"countries": []map[string]any{
                {"code": "BE", "name": "بلژیک", "cities": []map[string]any{{"code": "bru", "name": "بروکسل"}}},
                {"code": "DE", "name": "آلمان", "cities": []map[string]any{{"code": "fra", "name": "فرانکفورت"}}},
                {"code": "NL", "name": "هلند", "cities": []map[string]any{{"code": "ams", "name": "آمستردام"}}},
                {"code": "SE", "name": "سوئد", "cities": []map[string]any{{"code": "sto", "name": "استکهلم"}}},
        }}

        mux := http.NewServeMux()
        mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
                if r.URL.Path != "/" {
                        http.NotFound(w, r)
                        return
                }
                w.Header().Set("Content-Type", "text/html; charset=utf-8")
                w.Write(WebUIHTML())
        })
        mux.HandleFunc("/api/state", func(w http.ResponseWriter, r *http.Request) {
                w.Header().Set("Content-Type", "application/json")
                json.NewEncoder(w).Encode(state)
        })
        mux.HandleFunc("/api/servers", func(w http.ResponseWriter, r *http.Request) {
                w.Header().Set("Content-Type", "application/json")
                json.NewEncoder(w).Encode(servers)
        })
        mux.HandleFunc("/api/logs", func(w http.ResponseWriter, r *http.Request) {
                w.Header().Set("Content-Type", "application/json")
                json.NewEncoder(w).Encode(map[string]any{
                        "lines": []map[string]any{
                                {"t": time.Now(), "l": "info", "m": "TLS+HTTP/2 to faor73.m1.fastly-masque.net is up; verifying real traffic"},
                                {"t": time.Now(), "l": "info", "m": "connected to faor73 (BE/bru) - traffic verified"},
                        },
                        "seq": 2,
                })
        })
        for _, ep := range []string{"/api/activate", "/api/connect", "/api/disconnect", "/api/settings", "/api/remove-key"} {
                mux.HandleFunc(ep, func(w http.ResponseWriter, r *http.Request) {
                        w.Header().Set("Content-Type", "application/json")
                        json.NewEncoder(w).Encode(state)
                })
        }
        fmt.Printf("mock UI server on http://127.0.0.1:%d/\n", port)
        if err := http.ListenAndServe(fmt.Sprintf("127.0.0.1:%d", port), mux); err != nil {
                panic(err)
        }
}
