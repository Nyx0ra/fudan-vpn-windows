package atrust

import (
	"bytes"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mythologyli/zju-connect/underlay"
)

func TestTunnelTLSConfigVerifiesCertificates(t *testing.T) {
	config := tunnelTLSConfig(nil)

	if config.InsecureSkipVerify {
		t.Fatal("tunnel certificate verification must be enabled")
	}
	if !config.SessionTicketsDisabled {
		t.Fatal("tunnel TLS session tickets must be disabled")
	}
	if config.VerifyConnection != nil || config.VerifyPeerCertificate != nil {
		t.Fatal("tunnel should use the standard certificate verifier")
	}
	if config.MinVersion != 0 || config.MaxVersion != 0 {
		t.Fatal("tunnel should use Go's TLS version defaults")
	}
}

func TestTunnelTLSConfigUsesKeyLogWriter(t *testing.T) {
	var writer bytes.Buffer
	config := tunnelTLSConfig(&writer)
	if config.KeyLogWriter != &writer {
		t.Fatal("tunnel TLS config did not receive the client key-log writer")
	}
}

func TestDialTLSContextUsesCallerKeyLogWriter(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()

	dialer, err := underlay.New(underlay.Options{AutoDetect: false})
	if err != nil {
		t.Fatal(err)
	}
	var keyLog bytes.Buffer
	base := &tls.Config{
		InsecureSkipVerify: true,
		KeyLogWriter:       &keyLog,
	}
	conn, err := dialTLSContext(t.Context(), dialer, "tcp", server.Listener.Addr().String(), base)
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if base.ServerName != "" {
		t.Fatalf("dialTLSContext mutated caller config ServerName to %q", base.ServerName)
	}
	if !strings.Contains(keyLog.String(), "CLIENT_") {
		t.Fatalf("key log does not contain client secrets: %q", keyLog.String())
	}
}
