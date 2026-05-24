package main

import "testing"

func TestNormalizeSiteURLIDNA(t *testing.T) {
	host, port, err := normalizeSiteURL("госуслуги.рф")
	if err != nil {
		t.Fatalf("normalizeSiteURL: %v", err)
	}
	if host != "xn--c1aapkosapc.xn--p1ai" {
		t.Fatalf("host = %q, want punycode", host)
	}
	if port != 443 {
		t.Fatalf("port = %d, want 443", port)
	}
}

func TestSplitHostPortIDNA(t *testing.T) {
	host, port, err := splitHostPort("госуслуги.рф:8443")
	if err != nil {
		t.Fatalf("splitHostPort: %v", err)
	}
	if host != "xn--c1aapkosapc.xn--p1ai" {
		t.Fatalf("host = %q, want punycode", host)
	}
	if port != 8443 {
		t.Fatalf("port = %d, want 8443", port)
	}
}
