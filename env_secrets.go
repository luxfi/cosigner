package cosigner

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/luxfi/cosigner/secrets"
)

// EnvSecretStore reads cosigner secrets from environment variables. The
// env var holds a URI passed through the vendored secrets.Resolver so
// operators can store the actual secret in env, file, or KMS:
//
//	FIREBLOCKS_COSIGNER_PEM__KEY="-----BEGIN PRIVATE KEY-----\n..."       (literal, back-compat)
//	FIREBLOCKS_COSIGNER_PEM__KEY="file:/var/run/secrets/fireblocks.pem"   (file-mounted, K8s secret pattern)
//	FIREBLOCKS_COSIGNER_PEM__KEY="kms:aws:cipher:<base64>"                 (KMS-wrapped, when provider registered)
//
// Bare secret contents (without a URI scheme) continue to work as literal
// values — every existing deploy keeps working unchanged.
//
// Env var conventions:
//
//	Utila:      UTILA_COSIGNER_PEM__<envSafe(org_id)>
//	Fireblocks: FIREBLOCKS_COSIGNER_PEM__<envSafe(api_key)>
//	Anchorage:  ANCHORAGE_COSIGNER_SECRET__<envSafe(api_key_id)>
//
// where envSafe uppercases the identifier and replaces every non-
// alphanumeric character with underscore (POSIX shell-safe).
//
// Zero value is usable. Concurrency-safe (os.Getenv is goroutine-safe and
// the secrets.Default() resolver is concurrency-safe by contract).
//
// This is the DEV / file-mount path. Production multi-tenant deployments
// use KMSSecretStore, which keys secrets by the verbatim public identifier
// (no lossy envSafe mapping).
type EnvSecretStore struct{}

// FetchUtila returns the service-account PEM for the given Utila org,
// reading from UTILA_COSIGNER_PEM__<envSafe(OrgID)>. The env value is
// passed through secrets.Resolver so file: / kms: schemes are supported.
// Returns ErrSecretNotConfigured wrapped with the env var name when unset.
func (EnvSecretStore) FetchUtila(ctx context.Context, intent *UtilaIntent) (string, error) {
	if intent == nil || intent.OrgID == "" {
		return "", fmt.Errorf("%w: utila intent missing org_id", ErrSecretNotConfigured)
	}
	envKey := "UTILA_COSIGNER_PEM__" + envSafe(intent.OrgID)
	raw := os.Getenv(envKey)
	if raw == "" {
		// Name the env var (the operator's lever) but NOT the raw tenant id —
		// the var name already encodes it, envSafe-transformed.
		return "", fmt.Errorf("%w: env %s unset", ErrSecretNotConfigured, envKey)
	}
	pem, err := secrets.Default().Resolve(ctx, raw)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", envKey, err)
	}
	return pem, nil
}

// FetchFireblocks returns the secret PEM for the given Fireblocks api_key,
// reading from FIREBLOCKS_COSIGNER_PEM__<envSafe(APIKey)>. Same URI-scheme
// resolution as FetchUtila — bare PEM values continue to work as literal.
// Returns ErrSecretNotConfigured wrapped with the env var name when unset.
func (EnvSecretStore) FetchFireblocks(ctx context.Context, intent *FireblocksIntent) (string, error) {
	if intent == nil || intent.APIKey == "" {
		return "", fmt.Errorf("%w: fireblocks intent missing api_key", ErrSecretNotConfigured)
	}
	envKey := "FIREBLOCKS_COSIGNER_PEM__" + envSafe(intent.APIKey)
	raw := os.Getenv(envKey)
	if raw == "" {
		// Name the env var (the operator's lever) but NOT the raw tenant id —
		// the var name already encodes it, envSafe-transformed.
		return "", fmt.Errorf("%w: env %s unset", ErrSecretNotConfigured, envKey)
	}
	pem, err := secrets.Default().Resolve(ctx, raw)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", envKey, err)
	}
	return pem, nil
}

// FetchAnchorage returns the secret API key for the given Anchorage
// api_key_id, reading from ANCHORAGE_COSIGNER_SECRET__<envSafe(APIKeyID)>.
// Same URI-scheme resolution as the others. Returns ErrSecretNotConfigured
// wrapped with the env var name when unset.
func (EnvSecretStore) FetchAnchorage(ctx context.Context, intent *AnchorageIntent) (string, error) {
	if intent == nil || intent.APIKeyID == "" {
		return "", fmt.Errorf("%w: anchorage intent missing api_key_id", ErrSecretNotConfigured)
	}
	envKey := "ANCHORAGE_COSIGNER_SECRET__" + envSafe(intent.APIKeyID)
	raw := os.Getenv(envKey)
	if raw == "" {
		// Name the env var (the operator's lever) but NOT the raw tenant id —
		// the var name already encodes it, envSafe-transformed.
		return "", fmt.Errorf("%w: env %s unset", ErrSecretNotConfigured, envKey)
	}
	secret, err := secrets.Default().Resolve(ctx, raw)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", envKey, err)
	}
	return secret, nil
}

// envSafe upper-cases s and replaces every non-alphanumeric byte with '_'.
// Lossy by design — env vars don't allow hyphens / dots; the lossy mapping
// is acceptable because env-var lookup is a dev fallback. KMS keys preserve
// the original identifier verbatim (see KMSSecretStore).
func envSafe(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
			b.WriteByte(c - ('a' - 'A'))
		case c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			b.WriteByte(c)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}
