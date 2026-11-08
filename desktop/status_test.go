package main

import (
	"errors"
	"github.com/mythologyli/zju-connect/desktopstatus"
	"strings"
	"testing"
	"time"
)

func TestOldGenerationCannotRestoreConnected(t *testing.T) {
	e := NewEngine()
	id := &processIdentity{PID: 2}
	e.identity = id
	e.generation = 2
	e.phase = PhaseLaunching
	e.setPhaseFor(1, id, PhaseConnected, "obsolete")
	if p, _ := e.Phase(); p != PhaseLaunching {
		t.Fatal("stale green restored", p)
	}
}
func TestClosedEngineRejectsQueuedStart(t *testing.T) {
	e := NewEngine()
	e.Close()
	if err := e.Start("", "", "unused"); !errors.Is(err, errEngineClosed) {
		t.Fatal("shutdown did not fence new starts", err)
	}
}

func TestStatusEvidenceCannotUseListenerAlone(t *testing.T) {
	now := time.Now()
	s := desktopstatus.Snapshot{Version: 1, PID: 42, ProcessStart: 99, RunID: "a", Updated: now.UnixNano(), TargetCIDR: "192.0.2.10/32"}
	if p, _ := evidencePhase(s, 42, 99, "a", now, ConnectionSettings{TargetIP: "192.0.2.10"}); p == PhaseConnected {
		t.Fatal("listener alone green")
	}
	s.Session = true
	s.PolicyValid = true
	s.Tunnels = 1
	if p, _ := evidencePhase(s, 42, 99, "a", now, ConnectionSettings{TargetIP: "192.0.2.10"}); p != PhaseConnected {
		t.Fatal(p)
	}
	for _, mutate := range []func(*desktopstatus.Snapshot){func(s *desktopstatus.Snapshot) { s.PID++ }, func(s *desktopstatus.Snapshot) { s.ProcessStart++ }, func(s *desktopstatus.Snapshot) { s.RunID = "old" }, func(s *desktopstatus.Snapshot) { s.Updated = now.Add(-6 * time.Second).UnixNano() }, func(s *desktopstatus.Snapshot) { s.Session = false }, func(s *desktopstatus.Snapshot) { s.Tunnels = 0 }} {
		bad := s
		mutate(&bad)
		if p, _ := evidencePhase(bad, 42, 99, "a", now, ConnectionSettings{TargetIP: "192.0.2.10"}); p == PhaseConnected {
			t.Fatal("invalid evidence green", bad)
		}
	}
	s.Tunnels = 0
	s.Reconnecting = true
	if p, _ := evidencePhase(s, 42, 99, "a", now, ConnectionSettings{TargetIP: "192.0.2.10"}); p != PhaseLaunching {
		t.Fatal("reconnect retained green")
	}
}
func TestLogsNeverExposeCallbackOrTicket(t *testing.T) {
	result := safeLog("request https://vpn.fudan.edu.cn/passport/v1/auth/httpsOauth2?code=SECRET&ticket=OTHER failed sid=TOKEN password=PASS")
	for _, secret := range []string{"SECRET", "OTHER", "TOKEN", "PASS", "httpsOauth2?"} {
		if strings.Contains(result, secret) {
			t.Fatal(result)
		}
	}
}
func TestTrayMenusRespectOwnershipAndConnecting(t *testing.T) {
	p := presentTray(PhaseLaunching, "等待", map[string]any{"canConnect": false, "canDisconnect": true})
	if p.CanConnect || !p.CanDisconnect {
		t.Fatal(p)
	}
	p = presentTray(PhaseFailed, "发现脚本引擎", map[string]any{"external": true, "canConnect": true, "canDisconnect": false})
	if p.ConnectLabel != "接管并重新连接" || p.CanDisconnect {
		t.Fatal(p)
	}
	p = presentTray(PhaseConnected, "https://example.com/?code=SECRET", map[string]any{"canConnect": true, "canDisconnect": true})
	if strings.Contains(p.Tooltip, "SECRET") || p.Label != "已连接" {
		t.Fatal(p)
	}
}
