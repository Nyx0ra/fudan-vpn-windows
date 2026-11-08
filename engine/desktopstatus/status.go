// Package desktopstatus carries deliberately credential-free engine evidence.
package desktopstatus

type Health struct {
	Session      bool `json:"session"`
	Tunnels      int  `json:"tunnels"`
	Reconnecting bool `json:"reconnecting"`
}
type Snapshot struct {
	Version          int    `json:"version"`
	PID              int    `json:"pid"`
	ProcessStart     int64  `json:"processStart"`
	RunID            string `json:"runId"`
	PolicyValid      bool   `json:"policyValid"`
	TargetCIDR       string `json:"targetCIDR"`
	TLSCompatibility bool   `json:"tlsCompatibility"`
	Updated          int64  `json:"updated"`
	Health
}
