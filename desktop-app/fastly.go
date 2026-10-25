package main

// Fastly "client challenge" solver (port of FastlyChallengeSolver.kt).
// Solves pow / pat / clientmetrics challenges and installs the issued
// cookies into the shared control-plane cookie jar for firefox.com hosts.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const solverUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"

const powAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

var challengePrefixRe = regexp.MustCompile(`/_fs-ch-[A-Za-z0-9]+`)
var initCallRe = regexp.MustCompile(`init\((\[[^\]]*\]),\s*"([^"]+)",\s*"([^"]+)"`)

var errNoChallengePage = errors.New("no challenge page")

type challengeSolverClient struct {
	jar    *simpleJar
	client *http.Client
}

func newChallengeSolver() *challengeSolverClient {
	jar := newSimpleJar()
	return &challengeSolverClient{
		jar: jar,
		client: &http.Client{
			Timeout:   60 * time.Second,
			Jar:       jar,
			Transport: controlPlane.Transport,
		},
	}
}

func (s *challengeSolverClient) get(url, accept string) (string, error) {
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", solverUserAgent)
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("GET %s returned HTTP %d", url, resp.StatusCode)
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return string(b), nil
}

func baseOrigin(prefixURL string) string {
	if idx := strings.Index(prefixURL, "/_fs-ch-"); idx > 0 {
		return prefixURL[:idx]
	}
	return prefixURL
}

func solvePow(base, targetHex string) (string, bool) {
	target, err := hex.DecodeString(targetHex)
	if err != nil || len(target) != 32 {
		return "", false
	}
	digest := sha256.New()
	for _, a := range powAlphabet {
		for _, b := range powAlphabet {
			suffix := string(a) + string(b)
			digest.Reset()
			digest.Write([]byte(base + suffix))
			if string(digest.Sum(nil)) == string(target) {
				return suffix, true
			}
		}
	}
	return "", false
}

func fetchPat(s *challengeSolverClient, prefixURL, token string) (string, error) {
	patURL := prefixURL + "/pat?token=" + url.QueryEscape(token)
	req, _ := http.NewRequest("POST", patURL, nil)
	req.Header.Set("Accept", "text/plain")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", solverUserAgent)
	req.Header.Set("Origin", baseOrigin(prefixURL))
	resp, err := s.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 400 || resp.StatusCode == 401 {
		return "", nil
	}
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("PAT request returned HTTP %d", resp.StatusCode)
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var out struct {
		Auth string `json:"auth"`
	}
	if json.Unmarshal(b, &out) != nil || out.Auth == "" {
		return "", errors.New("empty PAT auth token")
	}
	return out.Auth, nil
}

func clientMetricsAnswer() map[string]any {
	return map[string]any{
		"ty":       "clientmetrics",
		"webdriver": false,
		"bot_detection_result": map[string]any{
			"bot_detected": false,
			"bot_kind":     nil,
		},
		"browser_metrics": map[string]any{
			"client_data": "{}",
			"error_trace": nil,
		},
		"detector_results": map[string]any{},
		"v":                2,
	}
}

func answerChallenge(s *challengeSolverClient, prefixURL, token string, challenge map[string]any) (map[string]any, error) {
	ty, _ := challenge["ty"].(string)
	data, _ := challenge["data"].(map[string]any)
	switch ty {
	case "pow":
		base, _ := data["base"].(string)
		hash, _ := data["hash"].(string)
		answer, ok := solvePow(base, hash)
		if !ok {
			return nil, fmt.Errorf("no proof-of-work solution found for base %s", base)
		}
		return map[string]any{
			"ty":      "pow",
			"base":    base,
			"answer":  answer,
			"hmac":    data["hmac"],
			"expires": data["expires"],
		}, nil
	case "pat":
		auth, err := fetchPat(s, prefixURL, token)
		if err != nil {
			return nil, err
		}
		return map[string]any{"ty": "pat", "auth": auth}, nil
	case "clientmetrics":
		return clientMetricsAnswer(), nil
	default:
		return nil, fmt.Errorf("unsupported Fastly challenge type '%s' (captcha cannot be solved automatically)", ty)
	}
}

func (s *challengeSolverClient) solveOnHost(base string) error {
	page, err := s.get(base+"/", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	if err != nil {
		return err
	}
	if !strings.Contains(page, "/_fs-ch-") || !strings.Contains(page, "Client Challenge") {
		return errNoChallengePage
	}
	prefixMatch := challengePrefixRe.FindString(page)
	if prefixMatch == "" {
		return fmt.Errorf("challenge asset prefix not found on %s", base)
	}
	prefixURL := base + prefixMatch

	script, err := s.get(prefixURL+"/script.js?reload=true", "")
	if err != nil {
		return err
	}
	matches := initCallRe.FindAllStringSubmatch(script, -1)
	if len(matches) == 0 {
		return errors.New("challenge init() call not found in script")
	}
	last := matches[len(matches)-1]
	var challenges []map[string]any
	if err := json.Unmarshal([]byte(last[1]), &challenges); err != nil || len(challenges) == 0 {
		return fmt.Errorf("could not parse challenge list: %v", err)
	}
	token := last[2]

	const maxRounds = 3
	for round := 0; round < maxRounds; round++ {
		answers := make([]map[string]any, 0, len(challenges))
		for _, ch := range challenges {
			ans, err := answerChallenge(s, prefixURL, token, ch)
			if err != nil {
				return err
			}
			answers = append(answers, ans)
		}
		postBody, _ := json.Marshal(map[string]any{"token": token, "data": answers})
		req, _ := http.NewRequest("POST", prefixURL+"/fst-post-back", strings.NewReader(string(postBody)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", solverUserAgent)
		req.Header.Set("Origin", baseOrigin(prefixURL))
		resp, err := s.client.Do(req)
		if err != nil {
			return err
		}
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if resp.StatusCode != 200 {
			return fmt.Errorf("challenge post-back returned HTTP %d", resp.StatusCode)
		}
		var out struct {
			Status string `json:"status"`
			Ch     []map[string]any `json:"ch"`
			Tok    string `json:"tok"`
		}
		if err := json.Unmarshal(bodyBytes, &out); err != nil {
			return fmt.Errorf("unexpected post-back response: %v", err)
		}
		if out.Status == "success" {
			page, err := s.get(base+"/", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
			if err != nil {
				return err
			}
			if strings.Contains(page, "/_fs-ch-") && strings.Contains(page, "Client Challenge") {
				return errors.New("challenge cookie not accepted on this exit IP")
			}
			for _, kv := range s.jar.snapshotFor(base[len("https://"):]) {
				controlPlane.Jar.(*simpleJar).set(kv[0], kv[1], "firefox.com")
			}
			return nil
		}
		if len(out.Ch) == 0 || out.Tok == "" {
			return fmt.Errorf("unexpected post-back response: %.200s", string(bodyBytes))
		}
		challenges = out.Ch
		token = out.Tok
	}
	return errors.New("Fastly challenge did not complete within 3 rounds")
}

func solveFastlyChallenge() error {
	solver := newChallengeSolver()
	var lastErr error
	for _, base := range []string{"https://api.accounts.firefox.com", "https://accounts.firefox.com"} {
		err := solver.solveOnHost(base)
		if err == nil {
			return nil
		}
		if errors.Is(err, errNoChallengePage) {
			continue
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("host did not serve a Fastly challenge page")
	}
	return lastErr
}
