package cosigner

import (
	"context"
	"fmt"
	"strings"

	"github.com/luxfi/cosigner/secrets"
)

// KMSSecretStore is the PRODUCTION SecretStore. It resolves the secret half
// of each cosigner credential through a secrets.Resolver, keyed by the
// PUBLIC identifier in the intent. The secret (Fireblocks PEM, Utila
// service-account PEM, Anchorage API secret) lives in KMS and is fetched at
// dispatch time — it never crosses the wire.
//
// Path layout mirrors the TS backend's KMS convention, with the public
// identifier preserved VERBATIM (KMS keys allow hyphens/dots, so no lossy
// envSafe mapping — that distinguishes this from EnvSecretStore):
//
//	fireblocks: <Base>/fireblocks/<api_key>/secret_pem
//	utila:      <Base>/utila/<org_id>/sa_pem
//	anchorage:  <Base>/anchorage/<api_key_id>/api_secret
//
// Base is a resolver-URI PREFIX that selects the backing store and is
// dependency-free at this layer — the store just builds the URI and asks
// the Resolver. Examples:
//
//	"kms:lux:bridge/cosigners"   → a registered "lux" KMS provider decrypts
//	                               (register via secrets.RegisterKMS in main)
//	"file:/etc/cosigners"        → file-mounted secrets (self-contained, no
//	                               cloud SDK; K8s secret-mount pattern)
//
// Concurrency-safe when the Resolver is (Default() and file/kms providers
// are by contract).
type KMSSecretStore struct {
	// Resolver resolves the per-tenant secret URI. nil ⇒ secrets.Default().
	Resolver secrets.Resolver
	// Base is the resolver-URI prefix. Required — an empty Base makes every
	// fetch fail loudly rather than resolving an unscoped path.
	Base string
}

// NewKMSSecretStore returns a KMSSecretStore rooted at base, using the
// default resolver (literal/env/file/kms schemes). For a custom resolver
// chain, construct the struct directly and set Resolver.
func NewKMSSecretStore(base string) *KMSSecretStore {
	return &KMSSecretStore{Base: base}
}

// FetchUtila resolves <Base>/utila/<org_id>/sa_pem.
func (k *KMSSecretStore) FetchUtila(ctx context.Context, intent *UtilaIntent) (string, error) {
	if intent == nil || intent.OrgID == "" {
		return "", fmt.Errorf("%w: utila intent missing org_id", ErrSecretNotConfigured)
	}
	return k.resolve(ctx, "utila", intent.OrgID, "sa_pem")
}

// FetchFireblocks resolves <Base>/fireblocks/<api_key>/secret_pem.
func (k *KMSSecretStore) FetchFireblocks(ctx context.Context, intent *FireblocksIntent) (string, error) {
	if intent == nil || intent.APIKey == "" {
		return "", fmt.Errorf("%w: fireblocks intent missing api_key", ErrSecretNotConfigured)
	}
	return k.resolve(ctx, "fireblocks", intent.APIKey, "secret_pem")
}

// FetchAnchorage resolves <Base>/anchorage/<api_key_id>/api_secret.
func (k *KMSSecretStore) FetchAnchorage(ctx context.Context, intent *AnchorageIntent) (string, error) {
	if intent == nil || intent.APIKeyID == "" {
		return "", fmt.Errorf("%w: anchorage intent missing api_key_id", ErrSecretNotConfigured)
	}
	return k.resolve(ctx, "anchorage", intent.APIKeyID, "api_secret")
}

// resolve builds the per-tenant URI from the path convention and hands it
// to the Resolver. The public id is used verbatim; the URI is never logged.
func (k *KMSSecretStore) resolve(ctx context.Context, kind, id, leaf string) (string, error) {
	if k.Base == "" {
		return "", fmt.Errorf("cosigner: KMSSecretStore.Base is empty — refusing to resolve an unscoped %s secret", kind)
	}
	uri := strings.TrimRight(k.Base, "/") + "/" + kind + "/" + id + "/" + leaf
	r := k.Resolver
	if r == nil {
		r = secrets.Default()
	}
	secret, err := r.Resolve(ctx, uri)
	if err != nil {
		// The resolver error embeds the resolved URI — tenant id + secret
		// path. NEVER propagate it. SecretResolveError names the kind only;
		// the cause is preserved via Unwrap for errors.Is, never rendered.
		return "", &SecretResolveError{Kind: Kind(kind), cause: err}
	}
	if secret == "" {
		return "", fmt.Errorf("%w: %s secret resolved empty", ErrSecretNotConfigured, kind)
	}
	return secret, nil
}
