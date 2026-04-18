// Package canonical produces the deterministic byte sequence that pidchain
// hashes to compute a fingerprint. The layout is a stability contract:
// changing it invalidates every fingerprint every consumer has stored. There
// is intentionally no version tag — a layout change is a breaking release of
// a different library, not a versioned variant within pidchain.
package canonical

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
)

// recordSeparator (ASCII RS, 0x1E) terminates each per-ancestor record.
const recordSeparator = 0x1e

// ErrNullByteInField is returned when an Ancestor field contains a NUL byte.
// NUL is the intra-field terminator and cannot appear inside a field.
var ErrNullByteInField = errors.New("canonical: null byte in field")

// Ancestor is the canonical-input subset for a single chain position.
type Ancestor struct {
	TeamID           string
	BundleIdentifier string
	AuthorityLeaf    string
}

// Bytes returns the canonical byte sequence for chain.
//
// Layout:
//
//	<len(chain) as 4-byte big-endian uint32>   // ancestor count
//	for each ancestor in walk order:
//	  <TeamID bytes>           "\x00"
//	  <BundleIdentifier bytes> "\x00"
//	  <AuthorityLeaf bytes>    "\x00"
//	  "\x1e"                                   // record separator
//
// Returns ErrNullByteInField if any ancestor has a NUL in any of its three
// fields. Empty fields are permitted: an ancestor with all-empty fields
// still produces "\x00\x00\x00\x1e".
func Bytes(chain []Ancestor) ([]byte, error) {
	for _, a := range chain {
		if strings.ContainsRune(a.TeamID, 0) ||
			strings.ContainsRune(a.BundleIdentifier, 0) ||
			strings.ContainsRune(a.AuthorityLeaf, 0) {
			return nil, ErrNullByteInField
		}
	}

	var buf bytes.Buffer
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(chain)))
	buf.Write(lenBuf[:])

	for _, a := range chain {
		buf.WriteString(a.TeamID)
		buf.WriteByte(0)
		buf.WriteString(a.BundleIdentifier)
		buf.WriteByte(0)
		buf.WriteString(a.AuthorityLeaf)
		buf.WriteByte(0)
		buf.WriteByte(recordSeparator)
	}

	return buf.Bytes(), nil
}
