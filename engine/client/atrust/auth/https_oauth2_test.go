package auth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestOAuthLoginExchangesOriginalBrowserCallback(t *testing.T) {
	const rawQuery = "sfDomain=id.fudan.edu.cn&code=opaque+code%2b&state=state%2Fvalue"
	var requests int
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/passport/v1/auth/httpsOauth2":
			requests++
			if r.URL.RawQuery != rawQuery {
				t.Error("the OAuth request query was changed")
			}
			ticket := url.Values{"data": {`{"ticket":"sample-ticket"}`}}
			w.Header().Set("Location", "https://"+r.Host+"/portal/shortcut.html?"+ticket.Encode())
			w.WriteHeader(http.StatusFound)
		case "/passport/v1/public/authConfig":
			_, _ = w.Write([]byte(`{"code":0,"data":{}}`))
		default:
			t.Error("unexpected gateway request")
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	callback := server.URL + "/passport/v1/auth/httpsOauth2?" + rawQuery
	method, err := NewLoginMethod(LoginMethodOptions{
		AuthType:       "auth/httpsOauth2",
		Domain:         "id.fudan.edu.cn",
		OAuth2Callback: callback,
	})
	if err != nil {
		t.Fatal(err)
	}
	session := newTLSTestSession(server)
	if err := method.login(session, AuthInfo{}); err != nil {
		t.Fatal(err)
	}
	if requests != 1 || session.ticket != "sample-ticket" {
		t.Fatal("expected one callback exchange and an authenticated ticket")
	}
}

func TestOAuthLoginRejectsCallbackForOtherOrigin(t *testing.T) {
	session := NewSession("vpn.example.com", nil)
	for _, callback := range []string{
		"http://vpn.example.com/passport/v1/auth/httpsOauth2?code=secret-example",
		"https://other.example.com/passport/v1/auth/httpsOauth2?code=secret-example",
	} {
		err := session.loginAuthHttpsOauth2("", "id.example.com", "", callback)
		if err == nil || !strings.Contains(err.Error(), "origin") || strings.Contains(err.Error(), "secret-example") {
			t.Fatal("expected a redacted callback-origin error")
		}
	}
}

func TestOAuthLoginRedactsMalformedRedirect(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://bad%zz.example/?code=secret-example")
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()

	session := newTLSTestSession(server)
	err := session.httpsOauth2(server.URL + "/passport/v1/auth/httpsOauth2?code=secret-example")
	if err == nil || strings.Contains(err.Error(), "secret-example") {
		t.Fatal("expected a redacted redirect error")
	}
}
