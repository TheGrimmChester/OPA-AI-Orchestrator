package main

import "testing"

func TestMatchStatusOption(t *testing.T) {
	opts := []map[string]string{
		{"id": "1", "name": "Todo"},
		{"id": "2", "name": "In Progress"},
		{"id": "3", "name": "Done"},
	}
	if got := matchStatusOption(opts, "backlog"); got != "1" {
		t.Fatalf("backlog→Todo want 1 got %q", got)
	}
	if got := matchStatusOption(opts, "in_progress"); got != "2" {
		t.Fatalf("in_progress want 2 got %q", got)
	}
	if got := matchStatusOption(opts, "done"); got != "3" {
		t.Fatalf("done want 3 got %q", got)
	}
	if got := matchStatusOption(opts, "nope"); got != "" {
		t.Fatalf("unknown should be empty, got %q", got)
	}
}

func TestSplitOwnerRepo(t *testing.T) {
	o, r, ok := peerOwnerRepo("acme/demo")
	if !ok || o != "acme" || r != "demo" {
		t.Fatalf("got %s %s %v", o, r, ok)
	}
	if _, _, ok := peerOwnerRepo("bad"); ok {
		t.Fatal("expected fail")
	}
}
