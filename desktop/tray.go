package main

import "strings"

type desktopTray interface {
	Close()
	Notify()
}
type trayPresentation struct {
	Label, Tooltip, ConnectLabel string
	CanConnect, CanDisconnect    bool
}

func presentTray(p Phase, msg string, details map[string]any) trayPresentation {
	labels := map[Phase]string{PhaseIdle: "未连接", PhaseLaunching: "连接中", PhaseConnected: "已连接", PhaseFailed: "故障"}
	label := labels[p]
	connect := "连接"
	if p == PhaseConnected || p == PhaseFailed {
		connect = "重新连接"
	}
	if details["external"] == true {
		connect = "接管并重新连接"
	}
	tip := "复旦 VPN · " + label
	if msg != "" {
		tip += " · " + safeLog(msg)
	}
	tip = strings.ReplaceAll(tip, "\n", " ")
	return trayPresentation{Label: label, Tooltip: tip, ConnectLabel: connect, CanConnect: details["canConnect"] == true, CanDisconnect: details["canDisconnect"] == true}
}
