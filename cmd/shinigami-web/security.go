package main

import (
	"net"
	"net/http"
	"net/url"
	"strings"
)

// secureLocalAPI protects the local development API from DNS rebinding and
// cross-site browser requests. This is not authentication; keep the server
// bound to loopback and do not expose it through a public tunnel.
func secureLocalAPI(a *api, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		if !loopbackHost(r.Host) {
			a.fail(w, http.StatusForbidden, "invalid local host")
			return
		}
		if site := r.Header.Get("Sec-Fetch-Site"); site == "cross-site" {
			a.fail(w, http.StatusForbidden, "cross-site requests are not allowed")
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" && !allowedUIOrigin(origin) {
			a.fail(w, http.StatusForbidden, "cross-origin requests are not allowed")
			return
		}
		// A Referer is optional, but when present it must be from the local UI.
		if ref := r.Header.Get("Referer"); ref != "" {
			u, err := url.Parse(ref)
			if err != nil || !allowedUIOrigin(u.Scheme+"://"+u.Host) {
				a.fail(w, http.StatusForbidden, "invalid request referer")
				return
			}
		}
		if r.URL.Path == "/api/scan" && r.Method == http.MethodPost {
			media := strings.ToLower(strings.TrimSpace(strings.SplitN(r.Header.Get("Content-Type"), ";", 2)[0]))
			if media != "application/json" {
				a.fail(w, http.StatusUnsupportedMediaType, "application/json required")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func loopbackHost(host string) bool {
	name, port, err := net.SplitHostPort(host)
	if err != nil || port != "8787" {
		return false
	}
	return name == "127.0.0.1" || name == "localhost" || name == "[::1]" || name == "::1"
}

func allowedUIOrigin(raw string) bool {
	return raw == "http://127.0.0.1:5173" || raw == "http://localhost:5173"
}
