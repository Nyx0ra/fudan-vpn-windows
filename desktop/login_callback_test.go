package main

import "testing"

func TestWindowsLoginCallback(t *testing.T) {
	const callback = "https://vpn.fudan.edu.cn/passport/v1/auth/httpsOauth2"
	for _, tc := range []struct{ url, want string }{
		{callback + "?sfDomain=id.fudan.edu.cn&code=sample%2Bcode", callback + "?sfDomain=id.fudan.edu.cn&code=sample%2Bcode"},
		{callback + "?sfDomain=id.fudan.edu.cn&code=one&code=two", ""},
		{callback + "?sfDomain=other.example&code=sample", ""},
		{callback + "/extra?sfDomain=id.fudan.edu.cn&code=sample", ""},
		{"https://vpn.fudan.edu.cn/portal/?redirectid=1#/app_center", ""},
		{"https://other.example/passport/v1/auth/httpsOauth2?sfDomain=id.fudan.edu.cn&code=sample", ""},
		{"http://vpn.fudan.edu.cn/passport/v1/auth/httpsOauth2?sfDomain=id.fudan.edu.cn&code=sample", ""},
	} {
		if got := windowsLoginCallback(tc.url); got != tc.want {
			t.Errorf("windowsLoginCallback(%q) = %q, want %q", tc.url, got, tc.want)
		}
	}
}

func TestWindowsLoginCallbackPreservesOriginalQuery(t *testing.T) {
	const callback = "https://vpn.fudan.edu.cn/passport/v1/auth/httpsOauth2?sfDomain=id.fudan.edu.cn&code=opaque+code%2b&state=state%2Fvalue"
	if got := windowsLoginCallback(callback); got != callback {
		t.Fatal("the browser callback was changed before exchange")
	}
}
