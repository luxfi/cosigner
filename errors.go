package cosigner

import (
	"errors"
	"fmt"
)

// errors.go — the typed "not implemented" family.
//
// HONESTY INVARIANT: a cosigner family whose real vendor integration is
// not yet available in this module must FAIL LOUDLY — never silently
// accept a swap it cannot actually cosign. Such a family returns a
// Result with Status == StatusFailed whose Err wraps ErrNotImplemented
// and whose Reason names the precise missing artifact. This is the
// difference between "a stub dressed up as real" (forbidden) and "a real
// interface that is honestly blocked" (required).
//
// Two families ship blocked-on-vendor-spec today:
//   - Utila     (utila.go)     — blocked on a Go @luxfi/utila Connect-RPC
//     client / .proto source; only a TypeScript client exists.
//   - Anchorage (anchorage.go) — blocked on the Anchorage API spec / SDK;
//     no local artifact exists.
//
// Fireblocks (fireblocks.go) is REAL and is NOT part of this family.

// ErrNotImplemented is the sentinel every blocked cosigner family wraps.
// Callers branch on it with errors.Is(result.Err, ErrNotImplemented) to
// distinguish "this family is not built yet" from a real external
// rejection or a transport failure.
var ErrNotImplemented = errors.New("cosigner: family not implemented (blocked on vendor spec)")

// NotImplementedError is the typed error a blocked family produces. It
// names the family and the precise missing artifact so a follow-up PR
// knows exactly what unblocks it, and carries optional per-call detail
// (swap id, tenant identifiers) for traceability. It unwraps to
// ErrNotImplemented.
type NotImplementedError struct {
	// Family is the cosigner kind that is blocked (utila, anchorage…).
	Family Kind
	// MissingArtifact is the precise thing whose absence blocks the real
	// implementation — e.g. "@luxfi/utila Connect-RPC Go client / .proto".
	MissingArtifact string
	// Detail is optional per-call context (swap id, public identifiers).
	Detail string
}

func (e *NotImplementedError) Error() string {
	msg := fmt.Sprintf("%s cosigner not implemented — blocked on %s", e.Family, e.MissingArtifact)
	if e.Detail != "" {
		msg += "; " + e.Detail
	}
	return msg
}

// Unwrap lets errors.Is(err, ErrNotImplemented) succeed.
func (e *NotImplementedError) Unwrap() error { return ErrNotImplemented }

// notImplemented builds the StatusFailed Result a blocked family returns.
// The Result is wire-faithful (Reason carries the human-readable string);
// Err carries the typed error for programmatic branching (json:"-").
func notImplemented(intent Intent, missingArtifact, detail string) Result {
	err := &NotImplementedError{
		Family:          intent.Kind,
		MissingArtifact: missingArtifact,
		Detail:          detail,
	}
	return Result{
		Intent: intent,
		Status: StatusFailed,
		Reason: err.Error(),
		Err:    err,
	}
}
