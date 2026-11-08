package main

import "testing"

func TestPublicBinaryRejectsLegacyEasyConnectBeforeNetworking(t *testing.T) {
	old := conf
	defer func() { conf = old }()
	if code := initialize([]string{"-protocol", "easyconnect", "-username", "fixture", "-password", "fixture"}); code != 1 {
		t.Fatalf("unsupported legacy protocol returned %d, want rejection", code)
	}
}
