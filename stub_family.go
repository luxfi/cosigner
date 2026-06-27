package cosigner

import (
	"context"
	"fmt"
)

// StubFamilyDispatcher fails every cosign step with a clear "no family
// wired" reason. It is the explicit, LOUD default for any family slot a
// consumer hasn't configured — so an institutional user hitting an
// unconfigured family sees a clear failure instead of a silent drop where
// the swap completes without cosigning at all.
//
// Tests should swap in a purpose-built mock instead of using this — the
// stub's whole purpose is to produce a known failure shape, not to be
// mockable.
type StubFamilyDispatcher struct{}

// RunUtila returns StatusFailed with a clear "no family wired" reason.
func (StubFamilyDispatcher) RunUtila(_ context.Context, intent *UtilaIntent, _ string, opts DispatchOptions) Result {
	return Result{
		Intent: Intent{Kind: KindUtila, Utila: intent},
		Status: StatusFailed,
		Reason: fmt.Sprintf("utila cosign: no family wired — set CompositeFamilyDispatcher.UtilaFamily (swap=%s)", opts.SwapID),
	}
}

// RunFireblocks returns StatusFailed with a clear "no family wired" reason.
func (StubFamilyDispatcher) RunFireblocks(_ context.Context, intent *FireblocksIntent, _ string, opts DispatchOptions) Result {
	return Result{
		Intent: Intent{Kind: KindFireblocks, Fireblocks: intent},
		Status: StatusFailed,
		Reason: fmt.Sprintf("fireblocks cosign: no family wired — set CompositeFamilyDispatcher.FireblocksFamily to FireblocksRESTFamily{} (swap=%s)", opts.SwapID),
	}
}

// RunAnchorage returns StatusFailed with a clear "no family wired" reason.
func (StubFamilyDispatcher) RunAnchorage(_ context.Context, intent *AnchorageIntent, _ string, opts DispatchOptions) Result {
	return Result{
		Intent: Intent{Kind: KindAnchorage, Anchorage: intent},
		Status: StatusFailed,
		Reason: fmt.Sprintf("anchorage cosign: no family wired — set CompositeFamilyDispatcher.AnchorageFamily (swap=%s)", opts.SwapID),
	}
}
