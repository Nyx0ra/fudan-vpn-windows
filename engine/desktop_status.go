package main

import (
	"encoding/json"
	"github.com/mythologyli/zju-connect/configs"
	"github.com/mythologyli/zju-connect/desktopstatus"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type engineStatusReporter struct {
	mu     sync.RWMutex
	client any
}

func newEngineStatusReporter() *engineStatusReporter {
	r := &engineStatusReporter{}
	path := os.Getenv("FUDAN_VPN_STATUS_FILE")
	if path == "" {
		return r
	}
	runID := os.Getenv("FUDAN_VPN_RUN_ID")
	started := desktopstatus.ProcessStart()
	policy := validDesktopPolicy(conf)
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			h := desktopstatus.Health{}
			r.mu.RLock()
			c := r.client
			r.mu.RUnlock()
			if p, ok := c.(interface{ DesktopHealth() desktopstatus.Health }); ok {
				h = p.DesktopHealth()
			}
			s := desktopstatus.Snapshot{Version: 1, PID: os.Getpid(), ProcessStart: started, RunID: runID, PolicyValid: policy, TargetCIDR: conf.RouterStrictCIDR, TLSCompatibility: conf.FudanTunnelTLSCompat, Updated: time.Now().UnixNano(), Health: h}
			b, _ := json.Marshal(s)
			// An instance-specific temporary file avoids a shared-file partial read.
			tmp := path + "." + runID + ".tmp"
			if os.MkdirAll(filepath.Dir(path), 0700) == nil && os.WriteFile(tmp, b, 0600) == nil {
				_ = os.Rename(tmp, path)
			}
			<-ticker.C
		}
	}()
	return r
}
func (r *engineStatusReporter) setClient(c any) { r.mu.Lock(); r.client = c; r.mu.Unlock() }
func validDesktopPolicy(c configs.Config) bool {
	ip, prefix, err := net.ParseCIDR(c.RouterStrictCIDR)
	if err != nil || ip.To4() == nil {
		return false
	}
	ones, bits := prefix.Mask.Size()
	return ones == 32 && bits == 32 && c.Protocol == "atrust" && c.NoUpstream && c.RouterBind == "127.0.0.1:1082" && !c.TUNMode && !c.TCPTunnelMode
}
