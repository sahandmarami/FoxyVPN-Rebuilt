package main

// Local control plane: serves the embedded UI and the JSON API on 127.0.0.1.
// The WebView2 window loads this URL, and the browser fallback uses the very
// same address, so both paths render the identical interface.

import (
        "embed"
        "encoding/json"
        "fmt"
        "io"
        "io/fs"
        "net"
        "net/http"
        "strconv"
        "time"
)

//go:embed web
var webFS embed.FS

// WebUIHTML returns the embedded UI page (used by the dev mock server too).
func WebUIHTML() []byte {
        data, err := fs.ReadFile(webFS, "web/index.html")
        if err != nil {
                return nil
        }
        return data
}

type APIServer struct {
        core *Core
        log  *Logger
        ln   net.Listener
}

func NewAPIServer(core *Core, log *Logger, bind string, port int) (*APIServer, error) {
        var lastErr error
        for i := 0; i < 20; i++ {
                ln, err := net.Listen("tcp", net.JoinHostPort(bind, strconv.Itoa(port)))
                if err == nil {
                        return &APIServer{core: core, log: log, ln: ln}, nil
                }
                lastErr = err
                port++
        }
        return nil, fmt.Errorf("پورت آزاد برای رابط محلی پیدا نشد: %v", lastErr)
}

func (a *APIServer) Port() int { return a.ln.Addr().(*net.TCPAddr).Port }

func (a *APIServer) Start() {
        mux := http.NewServeMux()
        mux.HandleFunc("/", a.handleIndex)
        mux.HandleFunc("/api/state", a.handleState)
        mux.HandleFunc("/api/activate", a.handleActivate)
        mux.HandleFunc("/api/remove-key", a.handleRemoveKey)
        mux.HandleFunc("/api/connect", a.handleConnect)
        mux.HandleFunc("/api/disconnect", a.handleDisconnect)
        mux.HandleFunc("/api/servers", a.handleServers)
        mux.HandleFunc("/api/logs", a.handleLogs)
        mux.HandleFunc("/api/settings", a.handleSettings)
        mux.HandleFunc("/api/exit", a.handleExit)

        srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
        go srv.Serve(a.ln)
}

var exitRequested = make(chan struct{})

func (a *APIServer) handleIndex(w http.ResponseWriter, r *http.Request) {
        data, err := fs.ReadFile(webFS, "web/index.html")
        if err != nil {
                http.NotFound(w, r)
                return
        }
        w.Header().Set("Content-Type", "text/html; charset=utf-8")
        w.Header().Set("Cache-Control", "no-store")
        w.Write(data)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
        w.Header().Set("Content-Type", "application/json; charset=utf-8")
        w.WriteHeader(status)
        json.NewEncoder(w).Encode(v)
}

type apiError struct {
        Error string `json:"error"`
}

func (a *APIServer) handleState(w http.ResponseWriter, r *http.Request) {
        writeJSON(w, 200, a.core.Snapshot())
}

func (a *APIServer) handleActivate(w http.ResponseWriter, r *http.Request) {
        if r.Method != "POST" {
                writeJSON(w, 405, apiError{"method not allowed"})
                return
        }
        var in struct {
                Key string `json:"key"`
        }
        if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&in); err != nil {
                writeJSON(w, 400, apiError{"bad request"})
                return
        }
        if err := a.core.ActivateKey(in.Key); err != nil {
                writeJSON(w, 400, apiError{err.Error()})
                return
        }
        writeJSON(w, 200, a.core.Snapshot())
}

func (a *APIServer) handleRemoveKey(w http.ResponseWriter, r *http.Request) {
        if r.Method != "POST" {
                writeJSON(w, 405, apiError{"method not allowed"})
                return
        }
        if err := a.core.RemoveKey(); err != nil {
                writeJSON(w, 400, apiError{err.Error()})
                return
        }
        writeJSON(w, 200, a.core.Snapshot())
}

func (a *APIServer) handleConnect(w http.ResponseWriter, r *http.Request) {
        if r.Method != "POST" {
                writeJSON(w, 405, apiError{"method not allowed"})
                return
        }
        var in struct {
                Country string `json:"country"`
                City    string `json:"city"`
        }
        _ = json.NewDecoder(io.LimitReader(r.Body, 8<<10)).Decode(&in)
        if err := a.core.Connect(in.Country, in.City); err != nil {
                writeJSON(w, 400, apiError{err.Error()})
                return
        }
        writeJSON(w, 200, a.core.Snapshot())
}

func (a *APIServer) handleDisconnect(w http.ResponseWriter, r *http.Request) {
        if r.Method != "POST" {
                writeJSON(w, 405, apiError{"method not allowed"})
                return
        }
        go func() {
                a.core.Disconnect()
        }()
        writeJSON(w, 200, a.core.Snapshot())
}

func (a *APIServer) handleServers(w http.ResponseWriter, r *http.Request) {
        countries, err := a.core.servers.Refresh(false)
        if err != nil && len(countries) == 0 {
                writeJSON(w, 502, apiError{"دریافت فهرست سرورها ناموفق بود: " + err.Error()})
                return
        }
        type cityJSON struct {
                Code string `json:"code"`
                Name string `json:"name"`
        }
        type countryJSON struct {
                Code   string     `json:"code"`
                Name   string     `json:"name"`
                Cities []cityJSON `json:"cities"`
        }
        out := make([]countryJSON, 0, len(countries))
        for _, c := range countries {
                cj := countryJSON{Code: c.Code, Name: c.Name}
                for _, city := range c.Cities {
                        cj.Cities = append(cj.Cities, cityJSON{Code: city.Code, Name: city.Name})
                }
                out = append(out, cj)
        }
        writeJSON(w, 200, map[string]any{"countries": out})
}

func (a *APIServer) handleLogs(w http.ResponseWriter, r *http.Request) {
        after, _ := strconv.Atoi(r.URL.Query().Get("after"))
        lines, seq := a.core.log.Since(after)
        writeJSON(w, 200, map[string]any{"lines": lines, "seq": seq})
}

func (a *APIServer) handleSettings(w http.ResponseWriter, r *http.Request) {
        if r.Method != "POST" {
                writeJSON(w, 405, apiError{"method not allowed"})
                return
        }
        var in struct {
                SysProxy  *bool   `json:"sys_proxy"`
                AutoConn  *bool   `json:"auto_connect"`
                Country   *string `json:"country"`
                City      *string `json:"city"`
        }
        if err := json.NewDecoder(io.LimitReader(r.Body, 8<<10)).Decode(&in); err != nil {
                writeJSON(w, 400, apiError{"bad request"})
                return
        }
        if in.SysProxy != nil {
                a.core.SetSysProxyEnabled(*in.SysProxy)
        }
        if in.AutoConn != nil {
                a.core.store.SetAutoConnect(*in.AutoConn)
        }
        if in.Country != nil || in.City != nil {
                cc, ct := a.core.store.ChosenCountry()
                if in.Country != nil {
                        cc = *in.Country
                }
                if in.City != nil {
                        ct = *in.City
                }
                a.core.store.SetChosenCountry(cc, ct)
        }
        writeJSON(w, 200, a.core.Snapshot())
}

func (a *APIServer) handleExit(w http.ResponseWriter, r *http.Request) {
        if r.Method != "POST" {
                writeJSON(w, 405, apiError{"method not allowed"})
                return
        }
        writeJSON(w, 200, map[string]any{"ok": true})
        select {
        case exitRequested <- struct{}{}:
        default:
        }
}
