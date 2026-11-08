//go:build !windows

package main

import "context"

const automaticPlatformLogin = false

func runPlatformLoginChild() bool { return false }

func platformLogin(context.Context) (string, bool, error) {
	return "", false, nil
}
