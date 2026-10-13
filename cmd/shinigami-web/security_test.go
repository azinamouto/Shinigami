package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSecureLocalAPI(t *testing.T) {
	a := &api{}
	handler := secureLocalAPI(a, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	cases := []struct {
		name, host, origin, site, method, contentType string
		want                                          int
	}{
		{"valid local GET", "127.0.0.1:8787", "", "", "GET", "", 204},
		{"valid UI POST", "127.0.0.1:8787", "http://127.0.0.1:5173", "same-origin", "POST", "application/json", 204},
		{"DNS rebinding", "attacker.example:8787", "", "", "GET", "", 403},
		{"wrong port", "localhost:9999", "", "", "GET", "", 403},
		{"evil origin", "localhost:8787", "https://attacker.example", "", "GET", "", 403},
		{"cross site without origin", "localhost:8787", "", "cross-site", "GET", "", 403},
		{"form POST", "localhost:8787", "", "", "POST", "application/x-www-form-urlencoded", 415},
		{"missing JSON content type", "localhost:8787", "", "", "POST", "", 415},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			method := tc.method
			target := "/api/status"
			if method == "POST" {
				target = "/api/scan"
			}
			req := httptest.NewRequest(method, target, strings.NewReader("{}"))
			req.Host = tc.host
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			if tc.site != "" {
				req.Header.Set("Sec-Fetch-Site", tc.site)
			}
			if tc.contentType != "" {
				req.Header.Set("Content-Type", tc.contentType)
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			if w.Code != tc.want {
				t.Fatalf("status = %d, want %d", w.Code, tc.want)
			}
		})
	}
}
