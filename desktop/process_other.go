//go:build !windows

package main

import (
	"os"
	"os/exec"
)

func quietEngineCommand(*exec.Cmd) {}
func identifyProcess(pid int) (processIdentity, error) {
	exe, err := binaryPath()
	return processIdentity{PID: pid, Exe: exe}, err
}
func listenerIdentity(uint16) (*processIdentity, error) { return nil, nil }
func identityAlive(id processIdentity) bool {
	p, err := os.FindProcess(id.PID)
	return err == nil && p != nil
}
func stopIdentity(id processIdentity) error {
	p, err := os.FindProcess(id.PID)
	if err != nil {
		return err
	}
	return p.Kill()
}
