package atrust

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type remappedTunnelUnderlay struct{ address string }

func (d remappedTunnelUnderlay) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "tcp", d.address)
}
func (remappedTunnelUnderlay) ExcludeIP(net.IP) {}

func TestFudanTunnelCompatibilityIsLimitedToExplicitEndpoint(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-48 * time.Hour),
		NotAfter:     time.Now().Add(-24 * time.Hour),
		DNSNames:     []string{"wrong.example"},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	server.StartTLS()
	defer server.Close()

	for _, test := range []struct {
		name, address        string
		enabled, wantSuccess bool
	}{
		{"default remains strict", "175.186.248.37:441", false, false},
		{"explicit tunnel exception", "175.186.248.37:441", true, true},
		{"other port", "175.186.248.37:443", true, false},
		{"other IP", "175.186.248.38:441", true, false},
		{"login hostname", "vpn.fudan.edu.cn:443", true, false},
		{"hostname on tunnel port", "vpn.fudan.edu.cn:441", true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := NewClient(ClientOptions{
				UnderlayDialer:       remappedTunnelUnderlay{server.Listener.Addr().String()},
				FudanTunnelTLSCompat: test.enabled,
			})
			defer client.Close()
			conn, err := client.dialTunnelTLS(t.Context(), "tcp", test.address, tunnelTLSConfig(nil))
			if conn != nil {
				conn.Close()
			}
			if (err == nil) != test.wantSuccess {
				t.Fatalf("TLS success=%v, want %v (error=%v)", err == nil, test.wantSuccess, err)
			}
			// Exercise the node-selection path as well, not just the final tunnel:
			// a broad/always-strict probe policy must not defeat the scoped switch.
			nodes := getBestReachableNodes(t.Context(), map[string][]string{"fixture": {test.address}}, client.underlayDialer.DialContext, nil, test.enabled)
			if (nodes["fixture"] != "") != test.wantSuccess {
				t.Fatalf("node TLS selection success=%v, want %v", nodes["fixture"] != "", test.wantSuccess)
			}
		})
	}
}
