package auth

import (
	"net/url"
	"strings"
	"testing"
)

func TestPortalTicketReportsGatewayRejectionWithoutSecrets(t *testing.T) {
	const base = "vpn.example.com"
	query := url.Values{
		"err_info": {`{"errorCode":75500005,"errorMessage":"private-gateway-detail"}`},
		"code":     {"private-callback-code"},
	}
	_, err := parsePortalTicketFromRedirect("https://"+base+"/portal/shortcut.html?"+query.Encode(), base)
	if err == nil || !strings.Contains(err.Error(), "75500005") {
		t.Fatal("expected the gateway rejection code")
	}
	if strings.Contains(err.Error(), "private-") {
		t.Fatal("the rejection error exposed sensitive redirect data")
	}
}
