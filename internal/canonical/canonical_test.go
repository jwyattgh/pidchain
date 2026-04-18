package canonical

import (
	"bytes"
	"errors"
	"testing"
)

func TestBytes_EmptyChain(t *testing.T) {
	got, err := Bytes(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []byte{0x00, 0x00, 0x00, 0x00}
	if !bytes.Equal(got, want) {
		t.Fatalf("bytes mismatch:\n got %q\nwant %q", got, want)
	}
}

func TestBytes_SingleAncestorAllFieldsPopulated(t *testing.T) {
	chain := []Ancestor{{
		TeamID:           "Q6L2SF6YDW",
		BundleIdentifier: "com.anthropic.claudefordesktop",
		AuthorityLeaf:    "Developer ID Application: Anthropic PBC (Q6L2SF6YDW)",
	}}
	got, err := Bytes(chain)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var want bytes.Buffer
	want.Write([]byte{0x00, 0x00, 0x00, 0x01})
	want.WriteString("Q6L2SF6YDW")
	want.WriteByte(0x00)
	want.WriteString("com.anthropic.claudefordesktop")
	want.WriteByte(0x00)
	want.WriteString("Developer ID Application: Anthropic PBC (Q6L2SF6YDW)")
	want.WriteByte(0x00)
	want.WriteByte(0x1e)

	if !bytes.Equal(got, want.Bytes()) {
		t.Fatalf("bytes mismatch:\n got %q\nwant %q", got, want.Bytes())
	}
}

func TestBytes_ThreeAncestorChain(t *testing.T) {
	// Mirrors the prototype probe's CD-spawned chain: ad-hoc-signed self plus two
	// Anthropic-signed ancestors. Position 0 has empty TeamID and
	// AuthorityLeaf — those empty fields are still load-bearing positionally.
	chain := []Ancestor{
		{TeamID: "", BundleIdentifier: "a.out", AuthorityLeaf: ""},
		{TeamID: "Q6L2SF6YDW", BundleIdentifier: "disclaimer", AuthorityLeaf: "Developer ID Application: Anthropic PBC (Q6L2SF6YDW)"},
		{TeamID: "Q6L2SF6YDW", BundleIdentifier: "com.anthropic.claudefordesktop", AuthorityLeaf: "Developer ID Application: Anthropic PBC (Q6L2SF6YDW)"},
	}
	got, err := Bytes(chain)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var want bytes.Buffer
	want.Write([]byte{0x00, 0x00, 0x00, 0x03})
	// Position 0: all three fields empty except BundleIdentifier.
	want.WriteByte(0x00)
	want.WriteString("a.out")
	want.WriteByte(0x00)
	want.WriteByte(0x00)
	want.WriteByte(0x1e)
	// Position 1.
	want.WriteString("Q6L2SF6YDW")
	want.WriteByte(0x00)
	want.WriteString("disclaimer")
	want.WriteByte(0x00)
	want.WriteString("Developer ID Application: Anthropic PBC (Q6L2SF6YDW)")
	want.WriteByte(0x00)
	want.WriteByte(0x1e)
	// Position 2.
	want.WriteString("Q6L2SF6YDW")
	want.WriteByte(0x00)
	want.WriteString("com.anthropic.claudefordesktop")
	want.WriteByte(0x00)
	want.WriteString("Developer ID Application: Anthropic PBC (Q6L2SF6YDW)")
	want.WriteByte(0x00)
	want.WriteByte(0x1e)

	if !bytes.Equal(got, want.Bytes()) {
		t.Fatalf("bytes mismatch:\n got %q\nwant %q", got, want.Bytes())
	}
}

func TestBytes_PrefixDifferProducesDifferentOutput(t *testing.T) {
	shared := Ancestor{TeamID: "T", BundleIdentifier: "B", AuthorityLeaf: "A"}
	a := []Ancestor{shared, shared, {TeamID: "X", BundleIdentifier: "Y", AuthorityLeaf: "Z"}}
	b := []Ancestor{shared, shared, {TeamID: "X", BundleIdentifier: "Y", AuthorityLeaf: "Z2"}}

	bytesA, err := Bytes(a)
	if err != nil {
		t.Fatalf("Bytes(a): %v", err)
	}
	bytesB, err := Bytes(b)
	if err != nil {
		t.Fatalf("Bytes(b): %v", err)
	}
	if bytes.Equal(bytesA, bytesB) {
		t.Fatal("chains differing only at trailing position produced identical canonical bytes")
	}
}

func TestBytes_EmptyAncestorCountsDifferByLength(t *testing.T) {
	one, err := Bytes([]Ancestor{{}})
	if err != nil {
		t.Fatal(err)
	}
	two, err := Bytes([]Ancestor{{}, {}})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(one, two) {
		t.Fatal("length prefix did not distinguish 1 vs 2 empty ancestors")
	}
}

func TestBytes_NULInTeamID(t *testing.T) {
	_, err := Bytes([]Ancestor{{TeamID: "has\x00nul"}})
	if !errors.Is(err, ErrNullByteInField) {
		t.Fatalf("want ErrNullByteInField, got %v", err)
	}
}

func TestBytes_NULInBundleIdentifier(t *testing.T) {
	_, err := Bytes([]Ancestor{{BundleIdentifier: "has\x00nul"}})
	if !errors.Is(err, ErrNullByteInField) {
		t.Fatalf("want ErrNullByteInField, got %v", err)
	}
}

func TestBytes_NULInAuthorityLeaf(t *testing.T) {
	_, err := Bytes([]Ancestor{{AuthorityLeaf: "has\x00nul"}})
	if !errors.Is(err, ErrNullByteInField) {
		t.Fatalf("want ErrNullByteInField, got %v", err)
	}
}
