package main

import (
	"context"
	"os"
	"testing"
)

func TestWindowsLoginAttemptsUseSeparateProfiles(t *testing.T) {
	first, cleanFirst, err := newWindowsLoginCommand(context.Background(), "fudan-vpn.exe")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanFirst)
	second, cleanSecond, err := newWindowsLoginCommand(context.Background(), "fudan-vpn.exe")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanSecond)

	firstProfile, secondProfile := first.Args[2], second.Args[2]
	if firstProfile == secondProfile {
		t.Fatal("login attempts share a WebView2 profile")
	}
	for _, profile := range []string{firstProfile, secondProfile} {
		if info, err := os.Stat(profile); err != nil || !info.IsDir() {
			t.Fatalf("missing temporary login profile: %v", err)
		}
	}
	cleanFirst()
	if _, err := os.Stat(firstProfile); !os.IsNotExist(err) {
		t.Fatalf("temporary login profile was not removed: %v", err)
	}
	if _, err := os.Stat(secondProfile); err != nil {
		t.Fatalf("cleaning the first profile affected the second: %v", err)
	}
}
