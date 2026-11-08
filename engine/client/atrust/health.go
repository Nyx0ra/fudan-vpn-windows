package atrust

import (
	"github.com/mythologyli/zju-connect/desktopstatus"
	"sync/atomic"
	"time"
)

// DesktopHealth reports session validity and server response evidence, never SID.
// No connection is opened to an application server for this observation.
func (c *Client) DesktopHealth() desktopstatus.Health {
	sid, err := c.sessionSID()
	h := desktopstatus.Health{Session: err == nil && sid != ""}
	select {
	case <-c.lifecycleCtx.Done():
		h.Session = false
	default:
	}
	c.l3TunnelMu.Lock()
	t := c.l3Tunnel
	c.l3TunnelMu.Unlock()
	if t == nil {
		return h
	}
	t.connsMu.Lock()
	defer t.connsMu.Unlock()
	h.Reconnecting = len(t.connecting) > 0
	for _, conn := range t.conns {
		select {
		case <-conn.closeCh:
			continue
		default:
		}
		last := atomic.LoadInt64(&conn.lastServerFrame)
		if last > 0 && time.Since(time.Unix(0, last)) <= 15*time.Second {
			h.Tunnels++
		}
	}
	return h
}
