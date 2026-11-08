//go:build !windows

package main

import "fmt"

func startDesktopTray(*App) (desktopTray, error) {
	return nil, fmt.Errorf("当前平台未启用 Windows 托盘")
}
