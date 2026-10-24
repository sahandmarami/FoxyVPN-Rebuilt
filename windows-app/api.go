package main

// Local web panel: serves the embedded SPA and the JSON API on 127.0.0.1.

import (
	"embed"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"
)

//go:embed web/index.html
var webFS embed.FS

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
	return nil, fmt.Errorf("no free port for the local panel")
}

func (a *APIServer) Port() int { return a.ln.Addr().(*net.TCPAddr).Port }

func (a *APIServer) Start() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", a.handleIndex)
	mux.HandleFunc("/api/state", a.handleState)
	mux.HandleFunc("/api/login", a.handleLogin)
	mux.HandleFunc("/api/2fa", a.handle2FA)
	mux.HandleFunc("/api/logout", a.handleLogout)
	mux.HandleFunc("/api/connect", a.handleConnect)
	mux.HandleFunc("/api/disconnect", a.handleDisconnect)
	mux.HandleFunc("/api/servers", a.handleServers)
	mux.HandleFunc("/api/logs", a.handleLogs)
	mux.HandleFunc("/api/settings", a.handleSettings)

	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go srv.Serve(a.ln)
}

func (a *APIServer) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data, _ := webFS.ReadFile("web/index.html")
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

func (a *APIServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeJSON(w, 405, apiError{"method not allowed"})
		return
	}
	var in struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSON(w, 400, apiError{"bad request"})
		return
	}
	if err := a.core.Login(in.Email, in.Password); err != nil {
		writeJSON(w, 400, apiError{err.Error()})
		return
	}
	writeJSON(w, 200, a.core.Snapshot())
}

func (a *APIServer) handle2FA(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeJSON(w, 405, apiError{"method not allowed"})
		return
	}
	var in struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSON(w, 400, apiError{"bad request"})
		return
	}
	if err := a.core.Verify2FA(in.Code); err != nil {
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
		writeJSON(w, 502, apiError{"could not fetch the server list: " + err.Error()})
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
		SysProxy *bool `json:"sys_proxy"`
		Country  *string `json:"country"`
		City     *string `json:"city"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSON(w, 400, apiError{"bad request"})
		return
	}
	if in.SysProxy != nil {
		a.core.SetSysProxyEnabled(*in.SysProxy)
	}
	if in.Country != nil || in.City != nil {
		a.core.SetServerChoice(strOr(in.Country, ""), strOr(in.City, ""))
	}
	writeJSON(w, 200, a.core.Snapshot())
}

func strOr(s *string, def string) string {
	if s == nil {
		return def
	}
	return *s
}
