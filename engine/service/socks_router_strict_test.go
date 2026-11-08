package service

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/mythologyli/zju-connect/client"
	"github.com/mythologyli/zju-connect/dial"
	"github.com/mythologyli/zju-connect/router"
	"golang.org/x/net/proxy"
)

func TestStrictRouterTargetCannotUseReachableDirectConnection(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	probe, err := net.Dial("tcp", target.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	probe.Close()

	rules, err := router.Parse(strings.NewReader("MATCH,DIRECT\n"))
	if err != nil {
		t.Fatal(err)
	}
	vpn := dial.NewDialer(nil, nil, []client.IPResource{}, false, "", true)
	_, strict, _ := net.ParseCIDR("127.0.0.1/32")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	go ServeRouter(address, vpn, nil, rules, strict)
	for i := 0; i < 50; i++ {
		conn, err := net.DialTimeout("tcp", address, 50*time.Millisecond)
		if err == nil {
			conn.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	socks, err := proxy.SOCKS5("tcp", address, nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	conn, err := socks.(proxy.ContextDialer).DialContext(ctx, "tcp", target.Addr().String())
	if conn != nil {
		conn.Close()
	}
	if err == nil {
		t.Fatal("strict VPN target succeeded through a reachable direct path")
	}
}
