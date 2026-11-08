package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPublicSettingsDefaultStrictAndNoPersonalTarget(t *testing.T) {
	s, err := loadSettings(filepath.Join(t.TempDir(), "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	if s.TargetIP != "" || s.TunnelTLSCompatibility {
		t.Fatal("unsafe public defaults", s)
	}
	if _, err = connectionArgs(s, "rules.conf", true); err == nil {
		t.Fatal("unset target was allowed")
	}
}
func TestConnectionSettingsCanonicalTargetAndExplicitTLS(t *testing.T) {
	s := ConnectionSettings{TargetIP: " 192.0.2.10 "}
	args, err := connectionArgs(s, "rules.conf", true)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	for _, want := range []string{"-router-strict-cidr 192.0.2.10/32", "-no-upstream", "-reuse-session"} {
		if !strings.Contains(joined, want) {
			t.Fatal(joined)
		}
	}
	if strings.Contains(joined, "-fudan-tunnel-tls-compat") || strings.Contains(joined, "-oauth2-code") || strings.Contains(joined, "-tun-mode") {
		t.Fatal(joined)
	}
	s.TunnelTLSCompatibility = true
	args, err = connectionArgs(s, "rules.conf", false)
	if err != nil || !strings.Contains(strings.Join(args, " "), "-fudan-tunnel-tls-compat") {
		t.Fatal(args, err)
	}
	for _, ip := range []string{"", "hostname.example", "192.0.2.0/24", "::1", "127.0.0.1", "0.0.0.0", "224.0.0.1", "255.255.255.255"} {
		if _, err := connectionArgs(ConnectionSettings{TargetIP: ip}, "r", false); err == nil {
			t.Fatal("invalid target accepted", ip)
		}
	}
}
func TestSettingsRoundTripAndConfigurationIsolation(t *testing.T) {
	t.Setenv("APPDATA", t.TempDir())
	if filepath.Base(ConfigDir()) != "FudanVPNWindows" {
		t.Fatal("shares production settings", ConfigDir())
	}
	path := filepath.Join(t.TempDir(), "settings.json")
	want := ConnectionSettings{TargetIP: "192.0.2.20"}
	if err := saveSettings(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := loadSettings(path)
	if err != nil || got != want {
		t.Fatal(got, err)
	}
	b, _ := os.ReadFile(path)
	if strings.Contains(string(b), "code") || strings.Contains(string(b), "password") {
		t.Fatal("auth material in settings")
	}
}

func TestSettingsRejectMalformedOrOversizedFiles(t *testing.T) {
	for _, content := range []string{
		`{"targetIP":"192.0.2.10","password":"fixture"}`,
		`{"targetIP":"192.0.2.10"} {}`,
		`{"targetIP":"192.0.2.10"}` + strings.Repeat(" ", 9000),
	} {
		path := filepath.Join(t.TempDir(), "settings.json")
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadSettings(path); err == nil {
			t.Fatal("malformed/oversized settings accepted")
		}
	}
}

func TestSettingsCannotChangeDuringLoginOrEngineLaunch(t *testing.T) {
	t.Setenv("APPDATA", t.TempDir())
	a := &App{engine: NewEngine()}
	s := ConnectionSettings{TargetIP: "192.0.2.10"}
	a.loginMu.Lock()
	err := a.SaveConnectionSettings(s)
	a.loginMu.Unlock()
	if err == nil {
		t.Fatal("changed settings during login")
	}
	a.engine.phase = PhaseLaunching
	if err := a.SaveConnectionSettings(s); err == nil {
		t.Fatal("changed settings during launch")
	}
	a.engine.phase = PhaseIdle
	if err := a.SaveConnectionSettings(s); err != nil {
		t.Fatal(err)
	}
	if err := a.validateConnectionSettings(); err != nil {
		t.Fatal(err)
	}
}
