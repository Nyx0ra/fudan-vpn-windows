package atrust

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"

	"github.com/mythologyli/zju-connect/client"
)

func tlsConfig(config *tls.Config, keyLogWriter io.Writer) *tls.Config {
	if config == nil {
		config = &tls.Config{}
	} else {
		config = config.Clone()
	}
	if keyLogWriter != nil {
		config.KeyLogWriter = keyLogWriter
	}
	return config
}

// tunnelTLSConfig verifies the certificate against the selected node's address.
func tunnelTLSConfig(keyLogWriter io.Writer) *tls.Config {
	return tlsConfig(&tls.Config{
		SessionTicketsDisabled: true,
	}, keyLogWriter)
}

// This opt-in exception applies to the literal data-tunnel destination only.
// Authentication HTTP transports do not call this method.
func (c *Client) dialTunnelTLS(ctx context.Context, network, address string, config *tls.Config) (*tls.Conn, error) {
	config = endpointTunnelTLSConfig(c.fudanTunnelTLSCompat, network, address, config, c.tlsKeyLogWriter)
	return dialTLSContext(ctx, c.underlayDialer, network, address, config)
}

// Shared with node TLS latency probes so that selection cannot silently use a
// broader certificate exception than the eventual data-tunnel connection.
func endpointTunnelTLSConfig(compat bool, network, address string, config *tls.Config, writer io.Writer) *tls.Config {
	config = tlsConfig(config, writer)
	if compat && network == "tcp" && address == "175.186.248.37:441" {
		config.InsecureSkipVerify = true
	}
	return config
}

func dialTLSContext(ctx context.Context, dialer client.UnderlayDialer, network, address string, config *tls.Config) (*tls.Conn, error) {
	if dialer == nil {
		return nil, errors.New("underlay dialer is required")
	}
	rawConn, err := dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	if config == nil {
		config = &tls.Config{}
	} else {
		config = config.Clone()
	}
	if config.ServerName == "" {
		host, _, splitErr := net.SplitHostPort(address)
		if splitErr == nil {
			config.ServerName = host
		}
	}
	tlsConn := tls.Client(rawConn, config)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = rawConn.Close()
		return nil, err
	}
	return tlsConn, nil
}
