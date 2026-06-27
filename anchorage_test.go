package cosigner

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// TestAnchorageFamily_RunAnchorage_BlockedTypedError documents the current
// contract: until the Anchorage API spec / SDK lands, every AnchorageIntent
// fails LOUDLY with a typed *NotImplementedError. NOT a silent stub —
// errors.Is(Err, ErrNotImplemented) holds and the Reason names the precise
// missing artifact + the call context.
func TestAnchorageFamily_RunAnchorage_BlockedTypedError(t *testing.T) {
	got := AnchorageFamily{}.RunAnchorage(context.Background(),
		&AnchorageIntent{APIKeyID: "ak-anchor-7", VaultID: "vault-iron"},
		"unused-secret",
		DispatchOptions{SwapID: "swap_anch", TxHash: "0xabcd"},
	)
	if got.Status != StatusFailed {
		t.Fatalf("expected StatusFailed (real impl pending), got %s reason=%q", got.Status, got.Reason)
	}
	if !errors.Is(got.Err, ErrNotImplemented) {
		t.Fatalf("Result.Err should wrap ErrNotImplemented, got %v", got.Err)
	}
	var nie *NotImplementedError
	if !errors.As(got.Err, &nie) {
		t.Fatalf("Result.Err should be *NotImplementedError, got %T", got.Err)
	}
	if nie.Family != KindAnchorage {
		t.Errorf("NotImplementedError.Family = %q, want anchorage", nie.Family)
	}
	for _, want := range []string{"anchorage", "Anchorage Digital API", "swap_anch", "ak-anchor-7", "vault-iron"} {
		if !strings.Contains(got.Reason, want) {
			t.Errorf("reason should mention %q for grepability, got %q", want, got.Reason)
		}
	}
}

func TestAnchorageFamily_RunUtila_DelegatesToStubByDefault(t *testing.T) {
	got := AnchorageFamily{}.RunUtila(context.Background(),
		&UtilaIntent{OrgID: "o", ClientID: "c"}, "x",
		DispatchOptions{SwapID: "swap_au"})
	if got.Status != StatusFailed {
		t.Errorf("default Utila delegate = stub, want StatusFailed, got %s", got.Status)
	}
	if !strings.Contains(got.Reason, "no family wired") {
		t.Errorf("expected stub's reason, got %q", got.Reason)
	}
}

func TestAnchorageFamily_RunFireblocks_DelegatesToStubByDefault(t *testing.T) {
	got := AnchorageFamily{}.RunFireblocks(context.Background(),
		&FireblocksIntent{APIKey: "k"}, "x",
		DispatchOptions{SwapID: "swap_af"})
	if got.Status != StatusFailed {
		t.Errorf("default Fireblocks delegate = stub, want StatusFailed, got %s", got.Status)
	}
	if !strings.Contains(got.Reason, "no family wired") {
		t.Errorf("expected stub's reason, got %q", got.Reason)
	}
}

func TestAnchorageFamily_CustomDelegatesRoute(t *testing.T) {
	fam := AnchorageFamily{
		UtilaDelegate:      approvingUtilaDelegate{},
		FireblocksDelegate: approvingFireblocksDelegate{},
	}
	uGot := fam.RunUtila(context.Background(),
		&UtilaIntent{OrgID: "o", ClientID: "c"}, "x",
		DispatchOptions{SwapID: "swap_au2"})
	if uGot.Status != StatusApproved {
		t.Errorf("custom Utila delegate should approve, got %s", uGot.Status)
	}
	fGot := fam.RunFireblocks(context.Background(),
		&FireblocksIntent{APIKey: "k"}, "x",
		DispatchOptions{SwapID: "swap_af2"})
	if fGot.Status != StatusApproved {
		t.Errorf("custom Fireblocks delegate should approve, got %s", fGot.Status)
	}
}

// TestDispatch_AnchorageReachesFamily proves Anchorage is wired end-to-end
// through the dispatcher exactly like the other kinds: the secret is fetched
// (so the family is actually reached) and the blocked family fails loudly
// with the typed error carried on Result.Err.
func TestDispatch_AnchorageReachesFamily(t *testing.T) {
	secrets := fakeSecrets{
		anchorageSecrets: map[string]string{"ak-1": "anchorage-api-secret"},
	}
	d := NewDefault(secrets, AnchorageFamily{})
	results, err := d.Dispatch(context.Background(), DispatchOptions{
		SwapID: "swap_anch_disp",
		TxHash: "0xfeed",
		Cosigners: []Intent{
			{Kind: KindAnchorage, Anchorage: &AnchorageIntent{APIKeyID: "ak-1", VaultID: "v"}},
		},
	})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("len=%d want 1", len(results))
	}
	if results[0].Status != StatusFailed {
		t.Errorf("status=%s want failed (blocked family)", results[0].Status)
	}
	// errors.Is must see through the family's typed error — confirms the
	// secret was fetched and the family (not a config gate) produced this.
	if !errors.Is(results[0].Err, ErrNotImplemented) {
		t.Errorf("Result.Err should wrap ErrNotImplemented, got %v", results[0].Err)
	}
	if AllApproved(results) {
		t.Error("AllApproved should be false for a blocked family")
	}
}

// TestDispatch_AnchorageSecretMissing proves a missing Anchorage secret
// surfaces as a clean StatusFailed BEFORE the family is reached.
func TestDispatch_AnchorageSecretMissing(t *testing.T) {
	d := NewDefault(fakeSecrets{}, AnchorageFamily{})
	results, _ := d.Dispatch(context.Background(), DispatchOptions{
		SwapID: "swap_anch_nosecret",
		Cosigners: []Intent{
			{Kind: KindAnchorage, Anchorage: &AnchorageIntent{APIKeyID: "missing", VaultID: "v"}},
		},
	})
	if results[0].Status != StatusFailed {
		t.Errorf("status=%s want failed (secret missing)", results[0].Status)
	}
	if !strings.Contains(results[0].Reason, "fetch secret") {
		t.Errorf("reason should mention 'fetch secret', got: %q", results[0].Reason)
	}
	if !errors.Is(results[0].Err, ErrSecretNotConfigured) {
		t.Errorf("Result.Err should wrap ErrSecretNotConfigured, got %v", results[0].Err)
	}
}
