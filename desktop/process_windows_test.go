package main

import (
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestOwnershipHelper(t *testing.T) {
	if os.Getenv("FUDAN_PROCESS_HELPER") == "1" {
		time.Sleep(20 * time.Second)
		os.Exit(0)
	}
}
func TestStopIdentityRejectsReusedPIDAndWrongExecutable(t *testing.T) {
	exe, _ := os.Executable()
	cmd := exec.Command(exe, "-test.run=^TestOwnershipHelper$")
	cmd.Env = append(os.Environ(), "FUDAN_PROCESS_HELPER=1")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	id, err := identifyProcess(cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []processIdentity{{PID: id.PID, Start: id.Start - 1, Exe: id.Exe}, {PID: id.PID, Start: id.Start, Exe: id.Exe + ".other"}} {
		if err := stopIdentity(bad); err == nil {
			t.Fatal("foreign identity accepted")
		}
		if !identityAlive(id) {
			t.Fatal("unowned process killed")
		}
	}
	if err := stopIdentity(id); err != nil {
		t.Fatal(err)
	}
	if identityAlive(id) {
		t.Fatal("owned process not stopped")
	}
}
func TestExitedEngineLosesConnectedAndCanRetry(t *testing.T) {
	exe, _ := os.Executable()
	cmd := exec.Command(exe, "-test.run=^TestOwnershipHelper$")
	cmd.Env = append(os.Environ(), "FUDAN_PROCESS_HELPER=1")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	id, err := identifyProcess(cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	e := NewEngine()
	e.identity = &id
	e.owned = true
	e.phase = PhaseConnected
	e.wasConnected = true
	if err = stopIdentity(id); err != nil {
		t.Fatal(err)
	}
	e.poll()
	if p, _ := e.Phase(); p != PhaseFailed {
		t.Fatal("dead engine retained connected", p)
	}
	if e.Details()["canConnect"] != true {
		t.Fatal("retry disabled after engine exit")
	}
	if e.Details()["canDisconnect"] != false {
		t.Fatal("disconnect still enabled for a dead engine")
	}
}
