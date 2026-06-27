package cosigner

import (
	"context"
	"fmt"
	"time"
)

// anchorage.go — Anchorage Digital cosigner family (regulated qualified
// custodian).
//
// STATUS: BLOCKED ON VENDOR SPEC. RunAnchorage returns a typed
// *NotImplementedError (Status == StatusFailed, errors.Is(Err,
// ErrNotImplemented) == true). It is NOT a silent stub — every Anchorage
// intent fails LOUDLY and names the precise missing artifact.
//
// What's missing: the Anchorage Digital API spec / SDK. Unlike Fireblocks
// (real REST + JWT) and Utila (a TypeScript Connect-RPC client exists),
// there is NO Anchorage artifact anywhere under ~/work/lux — no `.proto`,
// no Go/TS SDK, no OpenAPI, no API client. Anchorage's production API
// authenticates each request with a public API key (Api-Access-Key
// header) plus a request signature over a canonical payload, and scopes
// operations to a custody vault; but the exact endpoint shapes,
// signature canonicalization, and operation/approval state machine are
// not derivable from anything local. Implementing against a guessed wire
// format would be the "stub dressed up as real" this module forbids, so
// we stop at the honest interface boundary.
//
// The wire type (AnchorageIntent), the KindAnchorage discriminator, and
// the parseAnchorage validator all live in cosigner.go alongside the
// other kinds — Anchorage is wired through ValidateIntents and the
// dispatcher exactly like Utila and Fireblocks. Only the real network
// flow (RunAnchorage's body) is blocked.
//
// When the spec lands, fill in RunAnchorage:
//
//  1. Build a per-tenant client from intent.APIKeyID (public) + the
//     secret signing key the SecretStore returned (FetchAnchorage),
//     against intent.APIHost (or Anchorage's production host).
//  2. Create a message-sign / transfer operation scoped to
//     vaults/<vault_id> that attests to opts.TxHash.
//  3. Poll the operation to a terminal state and map it to:
//     - StatusApproved (Signature = attestation, ExternalID = op id)
//     - StatusRejected (policy / approval-workflow denial)
//     - StatusFailed   (transport / config error / timeout)

// anchorageMissingArtifact is the precise blocker named in every
// Anchorage not-implemented Result. One constant ⇒ identical, greppable
// message everywhere.
const anchorageMissingArtifact = "Anchorage Digital API spec / SDK " +
	"(no .proto, SDK, OpenAPI, or API client found under ~/work/lux)"

// AnchorageFamily implements FamilyDispatcher with — once the Anchorage
// API spec lands — the real qualified-custody co-sign flow. The other
// families delegate to their configured delegates (default
// StubFamilyDispatcher) so this family can be wired standalone.
type AnchorageFamily struct {
	// UtilaDelegate routes RunUtila calls when this family is wired
	// standalone. Zero ⇒ StubFamilyDispatcher.
	UtilaDelegate FamilyDispatcher

	// FireblocksDelegate routes RunFireblocks calls when this family is
	// wired standalone. Zero ⇒ StubFamilyDispatcher.
	FireblocksDelegate FamilyDispatcher

	// HTTPClient / PollInterval / Timeout / Now / Nonce land with the
	// real client, mirroring FireblocksRESTFamily's pluggable surface.
	// Timeout is declared now so the construction site is stable across
	// the future port.
	Timeout time.Duration
}

// RunAnchorage is the integration point for the real Anchorage client.
// Today it fails LOUDLY with a typed *NotImplementedError naming the
// missing artifact + the call context (swap id, api key id, vault) for
// traceability. The "all listed must approve" policy then refunds the
// swap — never a silent drop.
func (a AnchorageFamily) RunAnchorage(_ context.Context, intent *AnchorageIntent, _ string, opts DispatchOptions) Result {
	detail := fmt.Sprintf("swap=%s api_key_id=%s vault=%s",
		opts.SwapID, intent.APIKeyID, intent.VaultID)
	return notImplemented(Intent{Kind: KindAnchorage, Anchorage: intent}, anchorageMissingArtifact, detail)
}

// RunUtila delegates to the configured UtilaDelegate (default stub).
func (a AnchorageFamily) RunUtila(ctx context.Context, intent *UtilaIntent, secret string, opts DispatchOptions) Result {
	delegate := a.UtilaDelegate
	if delegate == nil {
		delegate = StubFamilyDispatcher{}
	}
	return delegate.RunUtila(ctx, intent, secret, opts)
}

// RunFireblocks delegates to the configured FireblocksDelegate (default stub).
func (a AnchorageFamily) RunFireblocks(ctx context.Context, intent *FireblocksIntent, secret string, opts DispatchOptions) Result {
	delegate := a.FireblocksDelegate
	if delegate == nil {
		delegate = StubFamilyDispatcher{}
	}
	return delegate.RunFireblocks(ctx, intent, secret, opts)
}
