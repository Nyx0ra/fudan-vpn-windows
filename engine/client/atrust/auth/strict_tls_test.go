package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAuthenticationHTTPSRejectsUntrustedCertificate(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	session := NewSession(strings.TrimPrefix(server.URL, "https://"), nil)
	if _, err := session.GetAuthInfoList(); err == nil {
		t.Fatal("authentication HTTPS accepted an untrusted certificate")
	}
}
