package cosigner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeResolver returns canned plaintext keyed by the exact resolved URI.
// It lets the KMS-store tests assert the per-tenant path the store builds
// without touching the global KMS registry or any real backend.
type fakeResolver struct{ m map[string]string }

func (f fakeResolver) Resolve(_ context.Context, uri string) (string, error) {
	v, ok := f.m[uri]
	if !ok {
		return "", fmt.Errorf("fakeResolver: nothing at %q", uri)
	}
	return v, nil
}

// TestKMSSecretStore_BuildsVerbatimPaths is the production-path contract:
// each public identifier is preserved VERBATIM in the resolver URI (hyphens
// AND dots survive — the env store's envSafe would have mangled them).
func TestKMSSecretStore_BuildsVerbatimPaths(t *testing.T) {
	r := fakeResolver{m: map[string]string{
		"kms:lux:bridge/cosigners/fireblocks/api-key.dotted/secret_pem": "fb-pem",
		"kms:lux:bridge/cosigners/utila/org-hyphen-1/sa_pem":            "utila-pem",
		"kms:lux:bridge/cosigners/anchorage/ak.id-9/api_secret":         "anch-secret",
	}}
	store := &KMSSecretStore{Resolver: r, Base: "kms:lux:bridge/cosigners"}
	ctx := context.Background()

	if got, err := store.FetchFireblocks(ctx, &FireblocksIntent{APIKey: "api-key.dotted"}); err != nil || got != "fb-pem" {
		t.Fatalf("fireblocks: got %q err %v", got, err)
	}
	if got, err := store.FetchUtila(ctx, &UtilaIntent{OrgID: "org-hyphen-1", ClientID: "c"}); err != nil || got != "utila-pem" {
		t.Fatalf("utila: got %q err %v", got, err)
	}
	if got, err := store.FetchAnchorage(ctx, &AnchorageIntent{APIKeyID: "ak.id-9", VaultID: "v"}); err != nil || got != "anch-secret" {
		t.Fatalf("anchorage: got %q err %v", got, err)
	}
}

// TestKMSSecretStore_TrailingSlashBaseNormalised proves Base with a trailing
// slash resolves the same path (no doubled slash).
func TestKMSSecretStore_TrailingSlashBaseNormalised(t *testing.T) {
	r := fakeResolver{m: map[string]string{
		"file:/etc/cosigners/fireblocks/k/secret_pem": "ok",
	}}
	store := &KMSSecretStore{Resolver: r, Base: "file:/etc/cosigners/"}
	got, err := store.FetchFireblocks(context.Background(), &FireblocksIntent{APIKey: "k"})
	if err != nil || got != "ok" {
		t.Fatalf("got %q err %v (trailing-slash Base should normalise)", got, err)
	}
}

func TestKMSSecretStore_EmptyBaseFailsLoud(t *testing.T) {
	store := &KMSSecretStore{Base: ""}
	_, err := store.FetchFireblocks(context.Background(), &FireblocksIntent{APIKey: "k"})
	if err == nil || !strings.Contains(err.Error(), "Base is empty") {
		t.Fatalf("empty Base should fail loud, got %v", err)
	}
}

func TestKMSSecretStore_MissingIDFails(t *testing.T) {
	store := &KMSSecretStore{Base: "kms:lux:x"}
	_, err := store.FetchAnchorage(context.Background(), &AnchorageIntent{VaultID: "v"}) // no APIKeyID
	if !errors.Is(err, ErrSecretNotConfigured) {
		t.Fatalf("missing api_key_id should yield ErrSecretNotConfigured, got %v", err)
	}
}

// TestKMSSecretStore_ResolverErrorNamesKindNotURI confirms a resolver error
// is wrapped with the kind for debuggability but does NOT echo the resolved
// URI (which embeds the tenant identifier) into the message.
func TestKMSSecretStore_ResolverErrorNamesKindNotURI(t *testing.T) {
	store := &KMSSecretStore{Resolver: fakeResolver{m: map[string]string{}}, Base: "kms:lux:x"}
	_, err := store.FetchFireblocks(context.Background(), &FireblocksIntent{APIKey: "supersecret-tenant-id"})
	if err == nil {
		t.Fatal("expected error when resolver has no secret")
	}
	if !strings.Contains(err.Error(), "fireblocks") {
		t.Errorf("error should name the kind, got %q", err.Error())
	}
	if strings.Contains(err.Error(), "supersecret-tenant-id") {
		t.Errorf("error should NOT echo the resolved URI / tenant id, got %q", err.Error())
	}
}

// TestKMSSecretStore_DefaultResolver_FileScheme exercises the real default
// resolver (nil Resolver ⇒ secrets.Default()) end-to-end over the file:
// scheme — the self-contained, cloud-SDK-free production path.
func TestKMSSecretStore_DefaultResolver_FileScheme(t *testing.T) {
	dir := t.TempDir()
	secretPath := filepath.Join(dir, "fireblocks", "key-1", "secret_pem")
	if err := os.MkdirAll(filepath.Dir(secretPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secretPath, []byte("-----FILE-PEM-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	store := NewKMSSecretStore("file:" + dir) // nil Resolver ⇒ secrets.Default()
	got, err := store.FetchFireblocks(context.Background(), &FireblocksIntent{APIKey: "key-1"})
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if got != "-----FILE-PEM-----" {
		t.Errorf("got %q, want trimmed file contents", got)
	}
}
