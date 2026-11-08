package ping

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func TestLatencyTLSProbeRejectsUntrustedCertificateByDefault(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	host, port, _ := net.SplitHostPort(server.Listener.Addr().String())
	n, _ := strconv.Atoi(port)
	probe := NewTCPing()
	probe.SetTarget(&Target{Host: host, Port: n, Timeout: time.Second})
	if _, _, err := probe.ping(context.Background()); err == nil {
		t.Fatal("latency probe accepted untrusted TLS outside an explicit tunnel exception")
	}
}
