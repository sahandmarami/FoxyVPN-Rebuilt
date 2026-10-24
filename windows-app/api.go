package main

// Local app server: serves the embedded phone-style UI (WebView2 hosts it)
// and the JSON API the UI talks to, bound to 127.0.0.1 only.

import (
        "embed"
        "encoding/json"
        "fmt"
        "io/fs"
        "net"
        "net/http"
        "strconv"
        "strings"
        "time"
)

//go:embed ui
var uiFS embed.FS

type APIServer struct {
        core *Core
        log  *Logger
        ln   net.Listener
}

func NewAPIServer(core *Core, log *Logger, bind string, port int) (*APIServer, error) {
        for i := 0; i < 20; i++ {
                ln, err := net.Listen("tcp", net.JoinHostPort(bind, strconv.Itoa(port)))
                if err == nil {
                        return &APIServer{core: core, log: log, ln: ln}, nil
                }
                port++
        }
        return nil, fmt.Errorf("no free port for the local app server")
}

func (a *APIServer) Port() int { return a.ln.Addr().(*net.TCPAddr).Port }

func (a *APIServer) Start() {
        sub, err := fs.Sub(uiFS, "ui")
        if err != nil {
                panic(err)
        }
        mux := http.NewServeMux()
        mux.Handle("/static/", http.StripPrefix("/static/", noStore(http.FileServer(http.FS(sub)))))
        mux.HandleFunc("/", a.handleIndex)
        mux.HandleFunc("/api/state", a.handleState)
        mux.HandleFunc("/api/key", a.handleKey)
        mux.HandleFunc("/api/logout", a.handleLogout)
        mux.HandleFunc("/api/connect", a.handleConnect)
        mux.HandleFunc("/api/disconnect", a.handleDisconnect)
        mux.HandleFunc("/api/servers", a.handleServers)
        mux.HandleFunc("/api/ping", a.handlePing)
        mux.HandleFunc("/api/pingall", a.handlePingAll)
        mux.HandleFunc("/api/choose", a.handleChoose)
        mux.HandleFunc("/api/sysproxy", a.handleSysProxy)
        mux.HandleFunc("/api/logs", a.handleLogs)

        srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
        go srv.Serve(a.ln)
}

func noStore(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                w.Header().Set("Cache-Control", "no-store")
                next.ServeHTTP(w, r)
        })
}

func (a *APIServer) handleIndex(w http.ResponseWriter, r *http.Request) {
        if r.URL.Path != "/" && r.URL.Path != "/index.html" {
                http.NotFound(w, r)
                return
        }
        w.Header().Set("Content-Type", "text/html; charset=utf-8")
        w.Header().Set("Cache-Control", "no-store")
        data, _ := uiFS.ReadFile("ui/index.html")
        w.Write(data)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
        w.Header().Set("Content-Type", "application/json; charset=utf-8")
        w.Header().Set("Cache-Control", "no-store")
        w.WriteHeader(status)
        json.NewEncoder(w).Encode(v)
}

type apiError struct {
        Error string `json:"error"`
}

func (a *APIServer) handleState(w http.ResponseWriter, r *http.Request) {
        writeJSON(w, 200, a.core.Snapshot())
}

// handleKey activates a pasted FV1 quota key (Android KeyEntryScreen flow).
func (a *APIServer) handleKey(w http.ResponseWriter, r *http.Request) {
        if r.Method != "POST" {
                writeJSON(w, 405, apiError{"method not allowed"})
                return
        }
        var in struct {
                Key string `json:"key"`
        }
        if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
                writeJSON(w, 400, apiError{"bad request"})
                return
        }
        if strings.TrimSpace(in.Key) == "" {
                writeJSON(w, 400, apiError{"کلید را وارد کنید"})
                return
        }
        if err := a.core.ActivateKey(in.Key); err != nil {
                writeJSON(w, 400, apiError{err.Error()})
                return
        }
        writeJSON(w, 200, a.core.Snapshot())
}

func (a *APIServer) handleLogout(w http.ResponseWriter, r *http.Request) {
        if r.Method != "POST" {
                writeJSON(w, 405, apiError{"method not allowed"})
                return
        }
        if err := a.core.Logout(); err != nil {
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
        if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
                writeJSON(w, 400, apiError{"bad request"})
                return
        }
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
        a.core.Disconnect()
        writeJSON(w, 200, a.core.Snapshot())
}

func (a *APIServer) handleServers(w http.ResponseWriter, r *http.Request) {
        countries, err := a.core.servers.Refresh(false)
        if err != nil && len(countries) == 0 {
                cached := a.core.servers.Countries()
                if len(cached) == 0 {
                        writeJSON(w, 502, apiError{"could not fetch the server list: " + err.Error()})
                        return
                }
                countries = cached
        }
        snap := a.core.Snapshot()
        out := make([]countryJSON, 0, len(countries))
        for _, c := range countries {
                cj := countryJSON{Code: c.Code, Name: c.Name}
                for _, city := range c.Cities {
                        hosts := make([]string, 0, len(city.Servers))
                        for _, s := range city.Servers {
                                hosts = append(hosts, s.Hostname)
                        }
                        cities := cityJSON{
                                Code:    city.Code,
                                Name:    city.Name,
                                Host:    firstNonEmpty(hosts),
                                Servers: len(city.Servers),
                        }
                        cj.Cities = append(cj.Cities, cities)
                }
                out = append(out, cj)
        }
        writeJSON(w, 200, map[string]any{
                "countries": out,
                "selected":  map[string]string{"country": snap.Country, "city": snap.City},
        })
}

func firstNonEmpty(list []string) string {
        for _, s := range list {
                if strings.TrimSpace(s) != "" {
                        return s
                }
        }
        return ""
}

type cityJSON struct {
        Code    string `json:"code"`
        Name    string `json:"name"`
        Host    string `json:"host,omitempty"`
        Servers int    `json:"servers"`
}

type countryJSON struct {
        Code   string     `json:"code"`
        Name   string     `json:"name"`
        Cities []cityJSON `json:"cities"`
}

// handlePing measures one city's TCP latency (server-list rows fill in live).
func (a *APIServer) handlePing(w http.ResponseWriter, r *http.Request) {
        cc, city := r.URL.Query().Get("cc"), r.URL.Query().Get("city")
        if cc == "" || city == "" {
                writeJSON(w, 400, apiError{"cc and city are required"})
                return
        }
        ms := a.core.PingProbe(cc, city)
        writeJSON(w, 200, map[string]int{"ms": ms})
}

func (a *APIServer) handlePingAll(w http.ResponseWriter, r *http.Request) {
        if r.Method != "POST" {
                writeJSON(w, 405, apiError{"method not allowed"})
                return
        }
        a.core.StartPingAll()
        writeJSON(w, 200, a.core.Snapshot())
}

// handleChoose stores the user's server choice (the ServerListScreen pick).
func (a *APIServer) handleChoose(w http.ResponseWriter, r *http.Request) {
        if r.Method != "POST" {
                writeJSON(w, 405, apiError{"method not allowed"})
                return
        }
        var in struct {
                Country string `json:"country"`
                City    string `json:"city"`
        }
        if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
                writeJSON(w, 400, apiError{"bad request"})
                return
        }
        a.core.SetServerChoice(in.Country, in.City)
        writeJSON(w, 200, a.core.Snapshot())
}

func (a *APIServer) handleSysProxy(w http.ResponseWriter, r *http.Request) {
        if r.Method != "POST" {
                writeJSON(w, 405, apiError{"method not allowed"})
                return
        }
        var in struct {
                On *bool `json:"on"`
        }
        if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.On == nil {
                writeJSON(w, 400, apiError{"bad request"})
                return
        }
        a.core.SetSysProxyEnabled(*in.On)
        writeJSON(w, 200, a.core.Snapshot())
}

func (a *APIServer) handleLogs(w http.ResponseWriter, r *http.Request) {
        after, _ := strconv.Atoi(r.URL.Query().Get("after"))
        lines, seq := a.core.log.Since(after)
        writeJSON(w, 200, map[string]any{"lines": lines, "seq": seq})
}
