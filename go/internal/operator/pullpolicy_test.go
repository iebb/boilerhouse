package operator

import "testing"

func TestImageTagIsMutable(t *testing.T) {
	cases := []struct {
		ref  string
		want bool
	}{
		{"repo/agent-runtime:latest", true},
		{"654654481873.dkr.ecr.ap-northeast-1.amazonaws.com/cordless/agent-runtime:latest", true},
		{"ghcr.io/org/img", true},           // untagged → latest
		{"host:5000/org/img", true},         // registry port, untagged
		{"host:5000/org/img:v1.2.3", false}, // pinned tag despite a registry :port
		{"repo/agent-runtime:abc123", false},
		{"ghcr.io/meetsmore/cordless/agent-runtime:0798185", false},
	}
	for _, c := range cases {
		if got := imageTagIsMutable(c.ref); got != c.want {
			t.Errorf("imageTagIsMutable(%q) = %v, want %v", c.ref, got, c.want)
		}
	}
}
