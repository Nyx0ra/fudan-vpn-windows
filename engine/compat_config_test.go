package main

import "testing"

func TestFudanCompatibilityRequiresExplicitEnablement(t *testing.T) {
	options, _, err := loadStartupOptions(nil, func() []string { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if options.Config.FudanTunnelTLSCompat || options.Config.RouterStrictCIDR != "" {
		t.Fatal("compatibility or strict routing unexpectedly enabled by default")
	}
	options, _, err = loadStartupOptions([]string{
		"-fudan-tunnel-tls-compat",
		"-router-strict-cidr", "192.0.2.10/32",
		"-no-upstream",
	}, func() []string { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if !options.Config.FudanTunnelTLSCompat || options.Config.RouterStrictCIDR != "192.0.2.10/32" ||
		!options.Config.NoUpstream || options.Config.TUNMode {
		t.Fatal("explicit desktop settings were not preserved")
	}
	if _, _, err := loadStartupOptions([]string{"-router-strict-cidr", "invalid"}, func() []string { return nil }); err == nil {
		t.Fatal("invalid strict routing CIDR was accepted")
	}
}
