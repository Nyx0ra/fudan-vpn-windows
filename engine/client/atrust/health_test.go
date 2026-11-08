package atrust

import (
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestHealthRequiresSessionAndLiveServerResponses(t *testing.T) {
	c := NewClient(ClientOptions{})
	defer c.Close()
	if c.DesktopHealth().Session {
		t.Fatal("missing session reported valid")
	}
	c.setSessionSID("secret-ticket", nil)
	if h := c.DesktopHealth(); !h.Session || h.Tunnels != 0 {
		t.Fatal(h)
	}
	conn := &l3TunnelConn{closeCh: make(chan struct{})}
	c.l3Tunnel = &L3Tunnel{conns: map[string]*l3TunnelConn{"default": conn}, closeCh: make(chan struct{}), conntrackMgrs: make(map[string]*conntrackMgr)}
	if c.DesktopHealth().Tunnels != 0 {
		t.Fatal("channel without server evidence reported healthy")
	}
	atomic.StoreInt64(&conn.lastServerFrame, time.Now().UnixNano())
	if c.DesktopHealth().Tunnels != 1 {
		t.Fatal("live response not recognized")
	}
	atomic.StoreInt64(&conn.lastServerFrame, time.Now().Add(-20*time.Second).UnixNano())
	if c.DesktopHealth().Tunnels != 0 {
		t.Fatal("stale response retained green")
	}
	atomic.StoreInt64(&conn.lastServerFrame, time.Now().UnixNano())
	close(conn.closeCh)
	if c.DesktopHealth().Tunnels != 0 {
		t.Fatal("closed channel retained green")
	}
	c.setSessionSID("", net.ErrClosed)
	if c.DesktopHealth().Session {
		t.Fatal("failed session retained green")
	}
	// The fake connection must not be closed through a nil TLS socket during cleanup.
	c.l3Tunnel = nil
}
