package cosigner

import (
	"errors"
	"strings"
	"testing"
)

func TestNotImplementedError_UnwrapsToSentinel(t *testing.T) {
	e := &NotImplementedError{Family: KindUtila, MissingArtifact: "the-go-client", Detail: "swap=s1"}
	if !errors.Is(e, ErrNotImplemented) {
		t.Fatal("NotImplementedError should unwrap to ErrNotImplemented")
	}
	msg := e.Error()
	for _, want := range []string{"utila", "the-go-client", "swap=s1"} {
		if !strings.Contains(msg, want) {
			t.Errorf("Error() missing %q: %q", want, msg)
		}
	}
}

func TestNotImplementedError_NoDetail_NoSeparator(t *testing.T) {
	e := &NotImplementedError{Family: KindAnchorage, MissingArtifact: "the-spec"}
	msg := e.Error()
	if strings.Contains(msg, ";") {
		t.Errorf("with no Detail there should be no '; ' separator, got %q", msg)
	}
	if !strings.Contains(msg, "anchorage") || !strings.Contains(msg, "the-spec") {
		t.Errorf("Error() should still name family + artifact, got %q", msg)
	}
}

func TestNotImplemented_BuildsFailedResultWithTypedErr(t *testing.T) {
	intent := Intent{Kind: KindUtila, Utila: &UtilaIntent{OrgID: "o", ClientID: "c"}}
	r := notImplemented(intent, "artifact-x", "detail-y")

	if r.Status != StatusFailed {
		t.Errorf("status = %s, want failed", r.Status)
	}
	if r.Intent.Kind != KindUtila {
		t.Errorf("intent kind not preserved: %v", r.Intent.Kind)
	}
	if r.Err == nil {
		t.Fatal("Result.Err must be set for a blocked family")
	}
	if !errors.Is(r.Err, ErrNotImplemented) {
		t.Errorf("Result.Err should wrap ErrNotImplemented, got %v", r.Err)
	}
	// Reason mirrors the typed error string exactly — one source of truth.
	if r.Reason != r.Err.Error() {
		t.Errorf("Reason (%q) should equal Err.Error() (%q)", r.Reason, r.Err.Error())
	}
	// Approved results never carry ErrNotImplemented — sanity-check the
	// gate helpers treat a blocked Result as non-approved.
	if AllApproved([]Result{r}) {
		t.Error("a blocked Result must not count as approved")
	}
}
