package cosigner

import (
	"context"
	"fmt"
	"time"
)

// utila.go — Utila Connect-RPC cosigner family.
//
// STATUS: BLOCKED ON VENDOR SPEC. RunUtila returns a typed
// *NotImplementedError (Status == StatusFailed, errors.Is(Err,
// ErrNotImplemented) == true). It is NOT a silent stub — every Utila
// intent fails LOUDLY and names the precise missing artifact.
//
// What's missing: a Go @luxfi/utila Connect-RPC client (or the .proto
// source to generate one). The only Utila client in the tree is the
// TypeScript package `@luxfi/utila` v3.0.0 — generated `*_pb.ts`
// Connect-RPC stubs under bridge/pkg/utila/src/lib/gen/utila/api/...,
// with NO `.proto` source and NO Go bindings committed. Hand-rolling the
// Utila protobuf + Connect-RPC wire format in Go without the spec would
// be exactly the "stub dressed up as real" this module forbids, so we
// stop at the honest interface boundary.
//
// When the Go client / proto lands, fill in RunUtila per the documented
// flow below — no other type or interface change is required. The
// structure mirrors FireblocksRESTFamily so the future port is a
// contained change to ONE method.
//
// Reference TS implementation (the flow to replicate):
// app/server/src/domain/cosigners.ts runUtila — initiateTransaction
// (evm_personal_sign over opts.TxHash, scoped to vaults/<vault_id>),
// then poll getTransaction until a terminal TransactionState_Enum:
//
//	approved (sig present): SIGNED=4, AWAITING_PUBLISH=5, PUBLISHED=6,
//	  MINED=7, CONFIRMED=13
//	rejected: DECLINED=9, CANCELED=11, DROPPED=12, EXPIRED=15
//	failed:   FAILED=8, REPLACED=10

// utilaMissingArtifact is the precise blocker named in every Utila
// not-implemented Result. Kept as one constant so the message is
// identical everywhere and trivially greppable.
const utilaMissingArtifact = "@luxfi/utila Connect-RPC Go client / .proto source " +
	"(only the TypeScript pkg/utila v3.0.0 generated _pb.ts client exists; no Go bindings or .proto committed)"

// UtilaConnectRPCFamily implements FamilyDispatcher with — once the real
// @luxfi/utila Go client lands — the real Connect-RPC transaction-
// approval flow on the Utila side. The other families delegate to their
// configured delegates (default StubFamilyDispatcher) so an operator who
// only wants real Utila doesn't accidentally force the others.
type UtilaConnectRPCFamily struct {
	// FireblocksDelegate routes RunFireblocks calls when this family is
	// wired standalone. Zero ⇒ StubFamilyDispatcher. Production wiring
	// that wants multiple real families should compose via
	// CompositeFamilyDispatcher instead of setting this field.
	FireblocksDelegate FamilyDispatcher

	// AnchorageDelegate routes RunAnchorage calls when this family is
	// wired standalone. Zero ⇒ StubFamilyDispatcher.
	AnchorageDelegate FamilyDispatcher

	// Timeout caps the entire Utila approval flow (create + polls or
	// webhook wait) once the real implementation lands. Currently unused
	// because RunUtila is honestly blocked.
	Timeout time.Duration

	// (Other knobs — HTTPClient, PollInterval, Now, Nonce, etc. — land
	// with the real client, mirroring FireblocksRESTFamily's pluggable
	// surface so tests can inject deterministic time + transport.)
}

// RunUtila is the integration point for the real Utila Connect-RPC
// client. Today it fails LOUDLY with a typed *NotImplementedError naming
// the missing artifact + the call context (swap id, org, client, vault)
// for traceability. The "all listed must approve" policy then moves the
// swap to refund so the user's deposit is returned — never a silent drop.
func (u UtilaConnectRPCFamily) RunUtila(_ context.Context, intent *UtilaIntent, _ string, opts DispatchOptions) Result {
	detail := fmt.Sprintf("swap=%s org=%s client=%s vault=%s",
		opts.SwapID, intent.OrgID, intent.ClientID, vaultOrDefault(intent.VaultID, "(tenant default)"))
	return notImplemented(Intent{Kind: KindUtila, Utila: intent}, utilaMissingArtifact, detail)
}

// RunFireblocks delegates to the configured FireblocksDelegate (default
// stub) so a standalone wiring still has defined behaviour for Fireblocks.
func (u UtilaConnectRPCFamily) RunFireblocks(ctx context.Context, intent *FireblocksIntent, secret string, opts DispatchOptions) Result {
	delegate := u.FireblocksDelegate
	if delegate == nil {
		delegate = StubFamilyDispatcher{}
	}
	return delegate.RunFireblocks(ctx, intent, secret, opts)
}

// RunAnchorage delegates to the configured AnchorageDelegate (default stub).
func (u UtilaConnectRPCFamily) RunAnchorage(ctx context.Context, intent *AnchorageIntent, secret string, opts DispatchOptions) Result {
	delegate := u.AnchorageDelegate
	if delegate == nil {
		delegate = StubFamilyDispatcher{}
	}
	return delegate.RunAnchorage(ctx, intent, secret, opts)
}

// CompositeFamilyDispatcher routes per-family calls to separately
// configured runners. This is THE composition mechanism — the one way to
// wire several real families together:
//
//	families := cosigner.CompositeFamilyDispatcher{
//	    FireblocksFamily: cosigner.FireblocksRESTFamily{Timeout: 60 * time.Second},
//	    UtilaFamily:      cosigner.UtilaConnectRPCFamily{Timeout: 60 * time.Second}, // blocked today
//	    AnchorageFamily:  cosigner.AnchorageFamily{Timeout: 60 * time.Second},       // blocked today
//	}
//	dispatcher := cosigner.NewDefault(secretStore, families)
//
// Any field may be nil — a nil family falls back to StubFamilyDispatcher
// for that family (loud failure). The recommended production wiring sets
// only the families it has real implementations for; intents for a nil
// family fail with the stub reason.
type CompositeFamilyDispatcher struct {
	// UtilaFamily is consulted on every RunUtila call. Zero ⇒ stub.
	UtilaFamily FamilyDispatcher
	// FireblocksFamily is consulted on every RunFireblocks call. Zero ⇒ stub.
	FireblocksFamily FamilyDispatcher
	// AnchorageFamily is consulted on every RunAnchorage call. Zero ⇒ stub.
	AnchorageFamily FamilyDispatcher
}

// RunUtila delegates to UtilaFamily (or the stub).
func (c CompositeFamilyDispatcher) RunUtila(ctx context.Context, intent *UtilaIntent, secret string, opts DispatchOptions) Result {
	delegate := c.UtilaFamily
	if delegate == nil {
		delegate = StubFamilyDispatcher{}
	}
	return delegate.RunUtila(ctx, intent, secret, opts)
}

// RunFireblocks delegates to FireblocksFamily (or the stub).
func (c CompositeFamilyDispatcher) RunFireblocks(ctx context.Context, intent *FireblocksIntent, secret string, opts DispatchOptions) Result {
	delegate := c.FireblocksFamily
	if delegate == nil {
		delegate = StubFamilyDispatcher{}
	}
	return delegate.RunFireblocks(ctx, intent, secret, opts)
}

// RunAnchorage delegates to AnchorageFamily (or the stub).
func (c CompositeFamilyDispatcher) RunAnchorage(ctx context.Context, intent *AnchorageIntent, secret string, opts DispatchOptions) Result {
	delegate := c.AnchorageFamily
	if delegate == nil {
		delegate = StubFamilyDispatcher{}
	}
	return delegate.RunAnchorage(ctx, intent, secret, opts)
}

// vaultOrDefault returns vault when non-empty, otherwise the supplied
// default placeholder. Tiny helper to keep not-implemented messages
// readable when the intent omits VaultID.
func vaultOrDefault(vault, def string) string {
	if vault == "" {
		return def
	}
	return vault
}
