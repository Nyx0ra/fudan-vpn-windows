package main

import (
	"github.com/mythologyli/zju-connect/configs"
	"testing"
)

func TestDesktopPolicyAcceptsStrictTLSAndOnlySingleHostVPN(t *testing.T) {
	c := configs.Config{Protocol: "atrust", NoUpstream: true, RouterStrictCIDR: "192.0.2.10/32", RouterBind: "127.0.0.1:1082"}
	if !validDesktopPolicy(c) {
		t.Fatal("strict TLS cannot be healthy")
	}
	c.FudanTunnelTLSCompat = true
	if !validDesktopPolicy(c) {
		t.Fatal("explicit compatibility cannot be healthy")
	}
	c.RouterStrictCIDR = "198.51.100.7/32"
	if !validDesktopPolicy(c) {
		t.Fatal("target is hardcoded")
	}
	for _, change := range []func(*configs.Config){func(c *configs.Config) { c.RouterStrictCIDR = "" }, func(c *configs.Config) { c.RouterStrictCIDR = "192.0.2.0/24" }, func(c *configs.Config) { c.NoUpstream = false }, func(c *configs.Config) { c.TUNMode = true }, func(c *configs.Config) { c.RouterBind = "0.0.0.0:1082" }} {
		bad := c
		change(&bad)
		if validDesktopPolicy(bad) {
			t.Fatal("unsafe desktop policy accepted", bad.RouterStrictCIDR)
		}
	}
}
