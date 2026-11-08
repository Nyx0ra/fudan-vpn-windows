package main

import (
	"testing"
	"time"
)

func TestDisconnectCannotBeOvertakenBeforeIdlePublication(t *testing.T) {
	e := NewEngine()
	e.phase = PhaseConnected
	entered := make(chan struct{})
	release := make(chan struct{})
	finished := make(chan struct{})
	e.onPhase = func(p Phase, _ string) {
		if p == PhaseIdle {
			close(entered)
			<-release
		}
	}
	go e.Disconnect()
	<-entered
	go func() { _ = e.Start("", "", "unused"); close(finished) }()
	select {
	case <-finished:
		close(release)
		t.Fatal("start overtook disconnect phase")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("start did not resume")
	}
}
