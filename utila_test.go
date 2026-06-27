package cosigner

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// TestUtilaConnectRPCFamily_RunUtila_BlockedTypedError documents the current
// contract: until the real Utila Connect-RPC Go client / .proto lands, every
// UtilaIntent fails LOUDLY with a typed *NotImplementedError. This is NOT a
// silent stub — errors.Is(Err, ErrNotImplemented) holds and the Reason names
// the precise missing artifact + the call context for grepability.
//
// When the real implementation lands, REPLACE THIS TEST with a real flow
// assertion — but keep "fail without secret" / "fail on transport error"
// coverage mirroring FireblocksRESTFamily.
func TestUtilaConnectRPCFamily_RunUtila_BlockedTypedError(t *testing.T) {
	got := UtilaConnectRPCFamily{}.RunUtila(context.Background(),
		&UtilaIntent{
			OrgID:    "tenant-x",
			ClientID: "lux-bridge",
			VaultID:  "v-42",
		},
		"unused-secret",
		DispatchOptions{SwapID: "swap_uscaffold", TxHash: "0xabcd"},
	)
	if got.Status != StatusFailed {
		t.Fatalf("expected StatusFailed (real impl pending), got %s reason=%q", got.Status, got.Reason)
	}
	// Typed-error contract: programmatic branching must work.
	if !errors.Is(got.Err, ErrNotImplemented) {
		t.Fatalf("Result.Err should wrap ErrNotImplemented, got %v", got.Err)
	}
	var nie *NotImplementedError
	if !errors.As(got.Err, &nie) {
		t.Fatalf("Result.Err should be *NotImplementedError, got %T", got.Err)
	}
	if nie.Family != KindUtila {
		t.Errorf("NotImplementedError.Family = %q, want utila", nie.Family)
	}
	// Reason names the blocker + the call context for grepability.
	for _, want := range []string{"utila", "@luxfi/utila", "swap_uscaffold", "tenant-x", "lux-bridge", "v-42"} {
		if !strings.Contains(got.Reason, want) {
			t.Errorf("reason should mention %q for grepability, got %q", want, got.Reason)
		}
	}
}

func TestUtilaConnectRPCFamily_RunUtila_DefaultVaultPlaceholder(t *testing.T) {
	// VaultID omitted — reason should say "(tenant default)" so a reader
	// knows the intent didn't specify a vault.
	got := UtilaConnectRPCFamily{}.RunUtila(context.Background(),
		&UtilaIntent{OrgID: "o", ClientID: "c"},
		"unused-secret",
		DispatchOptions{SwapID: "swap_dvault"},
	)
	if !strings.Contains(got.Reason, "(tenant default)") {
		t.Errorf("reason should label the default-vault case, got %q", got.Reason)
	}
}

func TestUtilaConnectRPCFamily_RunFireblocks_DelegatesToStubByDefault(t *testing.T) {
	got := UtilaConnectRPCFamily{}.RunFireblocks(context.Background(),
		&FireblocksIntent{APIKey: "k"},
		"unused",
		DispatchOptions{SwapID: "swap_uf"},
	)
	if got.Status != StatusFailed {
		t.Errorf("default Fireblocks delegate = stub, want StatusFailed, got %s", got.Status)
	}
	if !strings.Contains(got.Reason, "no family wired") {
		t.Errorf("expected stub's reason, got %q", got.Reason)
	}
}

func TestUtilaConnectRPCFamily_RunFireblocks_CustomDelegate(t *testing.T) {
	delegate := approvingFireblocksDelegate{}
	got := UtilaConnectRPCFamily{FireblocksDelegate: delegate}.RunFireblocks(
		context.Background(),
		&FireblocksIntent{APIKey: "k"},
		"unused",
		DispatchOptions{SwapID: "swap_uf2"},
	)
	if got.Status != StatusApproved {
		t.Errorf("custom delegate should approve, got %s reason=%q", got.Status, got.Reason)
	}
}

func TestUtilaConnectRPCFamily_RunAnchorage_DelegatesToStubByDefault(t *testing.T) {
	got := UtilaConnectRPCFamily{}.RunAnchorage(context.Background(),
		&AnchorageIntent{APIKeyID: "ak", VaultID: "v"},
		"unused",
		DispatchOptions{SwapID: "swap_ua"},
	)
	if got.Status != StatusFailed {
		t.Errorf("default Anchorage delegate = stub, want StatusFailed, got %s", got.Status)
	}
	if !strings.Contains(got.Reason, "no family wired") {
		t.Errorf("expected stub's reason, got %q", got.Reason)
	}
}

// approvingFireblocksDelegate is a test-only family that approves Fireblocks
// calls and panics on the others (asserts routing).
type approvingFireblocksDelegate struct{}

func (approvingFireblocksDelegate) RunUtila(_ context.Context, _ *UtilaIntent, _ string, _ DispatchOptions) Result {
	panic("approvingFireblocksDelegate.RunUtila should not be called")
}
func (approvingFireblocksDelegate) RunFireblocks(_ context.Context, intent *FireblocksIntent, _ string, _ DispatchOptions) Result {
	return Result{
		Intent:     Intent{Kind: KindFireblocks, Fireblocks: intent},
		Status:     StatusApproved,
		Signature:  "fb-test-sig",
		ExternalID: "fb-test-ext",
	}
}
func (approvingFireblocksDelegate) RunAnchorage(_ context.Context, _ *AnchorageIntent, _ string, _ DispatchOptions) Result {
	panic("approvingFireblocksDelegate.RunAnchorage should not be called")
}

// ───────────────────────────────────────────────────────────────────────
//  CompositeFamilyDispatcher — verifies routing in all three directions
// ───────────────────────────────────────────────────────────────────────

func TestCompositeFamilyDispatcher_AllNilFallsBackToStub(t *testing.T) {
	c := CompositeFamilyDispatcher{}

	utilaGot := c.RunUtila(context.Background(),
		&UtilaIntent{OrgID: "o", ClientID: "c"}, "x",
		DispatchOptions{SwapID: "swap_cu"})
	if utilaGot.Status != StatusFailed {
		t.Errorf("zero Utila → stub failure expected, got %s", utilaGot.Status)
	}

	fbGot := c.RunFireblocks(context.Background(),
		&FireblocksIntent{APIKey: "k"}, "x",
		DispatchOptions{SwapID: "swap_cf"})
	if fbGot.Status != StatusFailed {
		t.Errorf("zero Fireblocks → stub failure expected, got %s", fbGot.Status)
	}

	anchGot := c.RunAnchorage(context.Background(),
		&AnchorageIntent{APIKeyID: "ak", VaultID: "v"}, "x",
		DispatchOptions{SwapID: "swap_ca"})
	if anchGot.Status != StatusFailed {
		t.Errorf("zero Anchorage → stub failure expected, got %s", anchGot.Status)
	}
}

func TestCompositeFamilyDispatcher_RoutesPerFamily(t *testing.T) {
	c := CompositeFamilyDispatcher{
		UtilaFamily:      approvingUtilaDelegate{},      // approves Utila, panics on others
		FireblocksFamily: approvingFireblocksDelegate{}, // approves Fireblocks, panics on others
		AnchorageFamily:  approvingAnchorageDelegate{},  // approves Anchorage, panics on others
	}

	uGot := c.RunUtila(context.Background(),
		&UtilaIntent{OrgID: "o", ClientID: "c"}, "x",
		DispatchOptions{SwapID: "swap_cu2"})
	if uGot.Status != StatusApproved {
		t.Errorf("Utila family should approve, got %s reason=%q", uGot.Status, uGot.Reason)
	}

	fGot := c.RunFireblocks(context.Background(),
		&FireblocksIntent{APIKey: "k"}, "x",
		DispatchOptions{SwapID: "swap_cf2"})
	if fGot.Status != StatusApproved {
		t.Errorf("Fireblocks family should approve, got %s reason=%q", fGot.Status, fGot.Reason)
	}

	aGot := c.RunAnchorage(context.Background(),
		&AnchorageIntent{APIKeyID: "ak", VaultID: "v"}, "x",
		DispatchOptions{SwapID: "swap_ca2"})
	if aGot.Status != StatusApproved {
		t.Errorf("Anchorage family should approve, got %s reason=%q", aGot.Status, aGot.Reason)
	}
}

// TestCompositeFamilyDispatcher_MixedRealAndNil shows real Fireblocks + nil
// Utila/Anchorage ⇒ Fireblocks intents go to the real runner; the others
// fail loudly with the stub reason.
func TestCompositeFamilyDispatcher_MixedRealAndNil(t *testing.T) {
	c := CompositeFamilyDispatcher{
		// UtilaFamily + AnchorageFamily intentionally nil — fall back to stub
		FireblocksFamily: approvingFireblocksDelegate{},
	}

	uGot := c.RunUtila(context.Background(),
		&UtilaIntent{OrgID: "o", ClientID: "c"}, "x",
		DispatchOptions{SwapID: "swap_mix_u"})
	if uGot.Status != StatusFailed {
		t.Errorf("nil Utila → stub failure expected, got %s", uGot.Status)
	}

	fGot := c.RunFireblocks(context.Background(),
		&FireblocksIntent{APIKey: "k"}, "x",
		DispatchOptions{SwapID: "swap_mix_f"})
	if fGot.Status != StatusApproved {
		t.Errorf("real Fireblocks should approve, got %s", fGot.Status)
	}

	aGot := c.RunAnchorage(context.Background(),
		&AnchorageIntent{APIKeyID: "ak", VaultID: "v"}, "x",
		DispatchOptions{SwapID: "swap_mix_a"})
	if aGot.Status != StatusFailed {
		t.Errorf("nil Anchorage → stub failure expected, got %s", aGot.Status)
	}
}

// approvingAnchorageDelegate is a test-only family that approves Anchorage
// calls and panics on the others (asserts routing).
type approvingAnchorageDelegate struct{}

func (approvingAnchorageDelegate) RunUtila(_ context.Context, _ *UtilaIntent, _ string, _ DispatchOptions) Result {
	panic("approvingAnchorageDelegate.RunUtila should not be called")
}
func (approvingAnchorageDelegate) RunFireblocks(_ context.Context, _ *FireblocksIntent, _ string, _ DispatchOptions) Result {
	panic("approvingAnchorageDelegate.RunFireblocks should not be called")
}
func (approvingAnchorageDelegate) RunAnchorage(_ context.Context, intent *AnchorageIntent, _ string, _ DispatchOptions) Result {
	return Result{
		Intent:     Intent{Kind: KindAnchorage, Anchorage: intent},
		Status:     StatusApproved,
		Signature:  "anch-test-sig",
		ExternalID: "anch-test-ext",
	}
}
