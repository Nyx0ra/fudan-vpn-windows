package main

import (
	"net/url"
	"strings"
)

func windowsLoginCallback(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || !strings.EqualFold(u.Host, callHost) ||
		u.User != nil || u.EscapedPath() != callPath || u.Fragment != "" {
		return ""
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil || len(q["sfDomain"]) != 1 || q.Get("sfDomain") != authHost ||
		len(q["code"]) != 1 || strings.TrimSpace(q.Get("code")) == "" {
		return ""
	}
	return raw
}
