package main

import (
	"github.com/mythologyli/zju-connect/desktopstatus"
	"testing"
	"time"
)

func TestEvidenceRequiresMatchingTargetAndTLSMode(t *testing.T) {
	now := time.Now()
	want := ConnectionSettings{TargetIP: "192.0.2.10"}
	s := desktopstatus.Snapshot{Version: 1, PID: 42, ProcessStart: 99, RunID: "x", Updated: now.UnixNano(), PolicyValid: true, TargetCIDR: "192.0.2.10/32", Health: desktopstatus.Health{Session: true, Tunnels: 1}}
	if p, _ := evidencePhase(s, 42, 99, "x", now, want); p != PhaseConnected {
		t.Fatal(p)
	}
	s.TargetCIDR = "192.0.2.20/32"
	if p, _ := evidencePhase(s, 42, 99, "x", now, want); p == PhaseConnected {
		t.Fatal("wrong target green")
	}
	s.TargetCIDR = "192.0.2.10/32"
	s.TLSCompatibility = true
	if p, _ := evidencePhase(s, 42, 99, "x", now, want); p == PhaseConnected {
		t.Fatal("unrequested TLS exception green")
	}
	want.TunnelTLSCompatibility = true
	if p, _ := evidencePhase(s, 42, 99, "x", now, want); p != PhaseConnected {
		t.Fatal(p)
	}
}
