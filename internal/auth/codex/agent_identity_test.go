package codex

import (
	"context"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/nacl/box"
)

func TestGenerateAgentKeyMaterialDeterministic(t *testing.T) {
	// Fixed 64-byte material → reproducible key material.
	material := make([]byte, agentIdentityKeySeedBytes)
	for i := range material {
		material[i] = byte(i + 1)
	}
	a, err := generateAgentKeyMaterialFromSeed(material)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	b, err := generateAgentKeyMaterialFromSeed(material)
	if err != nil {
		t.Fatalf("generate second: %v", err)
	}
	if a.PrivateKeyPKCS8Base64 != b.PrivateKeyPKCS8Base64 {
		t.Fatalf("private keys differ for same seed")
	}
	if a.PublicKeySSH != b.PublicKeySSH {
		t.Fatalf("public keys differ for same seed")
	}
	if !strings.HasPrefix(a.PublicKeySSH, "ssh-ed25519 ") {
		t.Fatalf("public key missing ssh-ed25519 prefix: %q", a.PublicKeySSH)
	}
	// Round-trip: derive SSH public key from stored private key.
	pub, err := PublicKeySSHFromPrivateKeyPKCS8Base64(a.PrivateKeyPKCS8Base64)
	if err != nil {
		t.Fatalf("derive public key: %v", err)
	}
	if pub != a.PublicKeySSH {
		t.Fatalf("public key mismatch: got %q want %q", pub, a.PublicKeySSH)
	}
	// Domain separation: different material → different key.
	material2 := make([]byte, agentIdentityKeySeedBytes)
	for i := range material2 {
		material2[i] = byte(i + 2)
	}
	c, err := generateAgentKeyMaterialFromSeed(material2)
	if err != nil {
		t.Fatalf("generate alt: %v", err)
	}
	if c.PrivateKeyPKCS8Base64 == a.PrivateKeyPKCS8Base64 {
		t.Fatalf("expected different private keys for different material")
	}
}

func TestGenerateAgentKeyMaterialFromSeedLength(t *testing.T) {
	if _, err := generateAgentKeyMaterialFromSeed([]byte{1, 2, 3}); err == nil {
		t.Fatalf("expected length error")
	}
}

func TestSignAndVerifyAgentAssertion(t *testing.T) {
	material := make([]byte, agentIdentityKeySeedBytes)
	for i := range material {
		material[i] = byte(100 + i%50)
	}
	km, err := generateAgentKeyMaterialFromSeed(material)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	rec := &AgentIdentityRecord{
		AgentRuntimeID:        "runtime-abc",
		PrivateKeyPKCS8Base64: km.PrivateKeyPKCS8Base64,
		AccountID:             "acct-1",
	}
	// Build assertion with fixed timestamp via low-level helpers.
	timestamp := "2026-01-02T03:04:05Z"
	taskID := "task-xyz"
	sig, err := signAgentAssertionPayload(rec, taskID, timestamp)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	serialized, err := serializeAgentAssertion(rec.AgentRuntimeID, taskID, timestamp, sig)
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(serialized)
	if err != nil {
		t.Fatalf("decode base64url: %v", err)
	}
	// Keys must appear in BTreeMap order.
	wantOrder := `"agent_runtime_id":"runtime-abc","signature":"` + sig + `","task_id":"task-xyz","timestamp":"2026-01-02T03:04:05Z"`
	if !strings.Contains(string(raw), wantOrder) {
		t.Fatalf("JSON key order/content mismatch:\n got %s\n want substring %s", raw, wantOrder)
	}
	var env agentAssertionEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	// Verify signature with public key.
	priv, err := signingKeyFromPrivateKeyPKCS8Base64(km.PrivateKeyPKCS8Base64)
	if err != nil {
		t.Fatalf("parse priv: %v", err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	payload := rec.AgentRuntimeID + ":" + taskID + ":" + timestamp
	sigBytes, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	if !ed25519.Verify(pub, []byte(payload), sigBytes) {
		t.Fatalf("signature verification failed")
	}
	// AuthorizationHeaderForAgentTask returns AgentAssertion prefix.
	header, err := AuthorizationHeaderForAgentTask(rec, taskID)
	if err != nil {
		t.Fatalf("auth header: %v", err)
	}
	if !strings.HasPrefix(header, "AgentAssertion ") {
		t.Fatalf("header prefix: %q", header)
	}
	encoded := strings.TrimPrefix(header, "AgentAssertion ")
	if _, err := base64.RawURLEncoding.DecodeString(encoded); err != nil {
		t.Fatalf("header payload not raw base64url: %v", err)
	}
}

func TestNormalizeAgentIdentityMetadataFlat(t *testing.T) {
	km, err := GenerateAgentKeyMaterial()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	raw := map[string]any{
		"type":              "codex",
		"auth_mode":         AgentAuthMode,
		"email":             "u@example.com",
		"account_id":        "acc-1",
		"chatgpt_user_id":   "user-1",
		"plan_type":         "plus",
		"agent_runtime_id":  "rt-1",
		"agent_private_key": km.PrivateKeyPKCS8Base64,
	}
	out, err := NormalizeAgentIdentityMetadata(raw)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if out["auth_mode"] != AgentAuthMode {
		t.Fatalf("auth_mode: %v", out["auth_mode"])
	}
	if out["agent_runtime_id"] != "rt-1" {
		t.Fatalf("runtime: %v", out["agent_runtime_id"])
	}
	rec, err := AgentIdentityFromMetadata(out)
	if err != nil {
		t.Fatalf("from metadata: %v", err)
	}
	if rec.Email != "u@example.com" || rec.AccountID != "acc-1" {
		t.Fatalf("record fields: %+v", rec)
	}
}

func TestNormalizeAgentIdentityMetadataNested(t *testing.T) {
	km, err := GenerateAgentKeyMaterial()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	raw := map[string]any{
		"type":      "codex",
		"auth_mode": AgentAuthMode,
		"email":     "outer@example.com",
		"agent_identity": map[string]any{
			"agent_runtime_id":  "rt-nested",
			"agent_private_key": km.PrivateKeyPKCS8Base64,
			"account_id":        "acc-nested",
			"chatgpt_user_id":   "user-nested",
			"plan_type":         "pro",
		},
	}
	out, err := NormalizeAgentIdentityMetadata(raw)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if _, ok := out["agent_identity"]; ok {
		t.Fatalf("nested agent_identity should be flattened away")
	}
	if out["agent_runtime_id"] != "rt-nested" {
		t.Fatalf("runtime: %v", out["agent_runtime_id"])
	}
	if out["account_id"] != "acc-nested" {
		t.Fatalf("account_id: %v", out["account_id"])
	}
}

func TestNormalizeAgentIdentityMetadataJWT(t *testing.T) {
	km, err := GenerateAgentKeyMaterial()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	payload := map[string]any{
		"agent_runtime_id":  "rt-jwt",
		"agent_private_key": km.PrivateKeyPKCS8Base64,
		"account_id":        "acc-jwt",
		"email":             "jwt@example.com",
		"plan_type":         "plus",
	}
	payloadJSON, _ := json.Marshal(payload)
	// header.payload.sig with dummy header/sig
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	body := base64.RawURLEncoding.EncodeToString(payloadJSON)
	jwt := header + "." + body + ".sig"
	raw := map[string]any{
		"type":           "codex",
		"auth_mode":      AgentAuthMode,
		"agent_identity": jwt,
	}
	out, err := NormalizeAgentIdentityMetadata(raw)
	if err != nil {
		t.Fatalf("normalize jwt: %v", err)
	}
	if out["agent_runtime_id"] != "rt-jwt" {
		t.Fatalf("runtime: %v", out["agent_runtime_id"])
	}
	if out["email"] != "jwt@example.com" {
		t.Fatalf("email: %v", out["email"])
	}
}

func TestNormalizeAgentIdentityMetadataChatgptAccountIDAlias(t *testing.T) {
	km, err := GenerateAgentKeyMaterial()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	raw := map[string]any{
		"auth_mode":          AgentAuthMode,
		"agent_runtime_id":   "rt-1",
		"agent_private_key":  km.PrivateKeyPKCS8Base64,
		"chatgpt_account_id": "acc-from-alias",
	}
	out, err := NormalizeAgentIdentityMetadata(raw)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if out["account_id"] != "acc-from-alias" {
		t.Fatalf("account_id alias: %v", out["account_id"])
	}
}

func TestIsAgentIdentityMetadata(t *testing.T) {
	if IsAgentIdentityMetadata(nil) {
		t.Fatal("nil should be false")
	}
	if !IsAgentIdentityMetadata(map[string]any{"auth_mode": "agent_identity"}) {
		t.Fatal("auth_mode should match")
	}
	if !IsAgentIdentityMetadata(map[string]any{"agent_identity": map[string]any{}}) {
		t.Fatal("nested agent_identity should match")
	}
	if !IsAgentIdentityMetadata(map[string]any{
		"agent_runtime_id":  "x",
		"agent_private_key": "y",
	}) {
		t.Fatal("runtime+key should match")
	}
	if IsAgentIdentityMetadata(map[string]any{"access_token": "t"}) {
		t.Fatal("oauth-only should not match")
	}
}

func TestRegisterAgentTaskPlainTaskID(t *testing.T) {
	km, err := GenerateAgentKeyMaterial()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	rec := &AgentIdentityRecord{
		AgentRuntimeID:        "rt-register",
		PrivateKeyPKCS8Base64: km.PrivateKeyPKCS8Base64,
		AccountID:             "acc",
	}
	var sawAuth bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			sawAuth = true
		}
		if !strings.HasSuffix(r.URL.Path, "/v1/agent/rt-register/task/register") {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		var req registerTaskRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Timestamp == "" || req.Signature == "" {
			t.Errorf("missing timestamp/signature")
		}
		// Verify signature over runtime_id:timestamp
		priv, _ := signingKeyFromPrivateKeyPKCS8Base64(km.PrivateKeyPKCS8Base64)
		pub := priv.Public().(ed25519.PublicKey)
		sigBytes, _ := base64.StdEncoding.DecodeString(req.Signature)
		payload := rec.AgentRuntimeID + ":" + req.Timestamp
		if !ed25519.Verify(pub, []byte(payload), sigBytes) {
			t.Errorf("task register signature invalid")
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"task_id": "task-from-server"})
	}))
	defer srv.Close()

	taskID, err := RegisterAgentTask(context.Background(), srv.Client(), srv.URL, rec)
	if err != nil {
		t.Fatalf("register task: %v", err)
	}
	if taskID != "task-from-server" {
		t.Fatalf("task id: %q", taskID)
	}
	if sawAuth {
		t.Fatalf("task register must not send Authorization header")
	}
}

func TestRegisterAgentTaskEncryptedTaskID(t *testing.T) {
	km, err := GenerateAgentKeyMaterial()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	rec := &AgentIdentityRecord{
		AgentRuntimeID:        "rt-enc",
		PrivateKeyPKCS8Base64: km.PrivateKeyPKCS8Base64,
		AccountID:             "acc",
	}
	plainTask := "task-encrypted-plain"
	// Seal for recipient public key.
	priv, err := signingKeyFromPrivateKeyPKCS8Base64(km.PrivateKeyPKCS8Base64)
	if err != nil {
		t.Fatalf("priv: %v", err)
	}
	_, curvePub, err := curve25519KeyPairFromEd25519PrivateKey(priv)
	if err != nil {
		t.Fatalf("curve: %v", err)
	}
	sealed, err := box.SealAnonymous(nil, []byte(plainTask), curvePub, nil)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	encB64 := base64.StdEncoding.EncodeToString(sealed)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"encrypted_task_id": encB64})
	}))
	defer srv.Close()

	taskID, err := RegisterAgentTask(context.Background(), srv.Client(), srv.URL, rec)
	if err != nil {
		t.Fatalf("register task: %v", err)
	}
	if taskID != plainTask {
		t.Fatalf("decrypted task id: got %q want %q", taskID, plainTask)
	}
}

func TestDecryptEncryptedTaskIDRoundTrip(t *testing.T) {
	km, err := GenerateAgentKeyMaterial()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	priv, err := signingKeyFromPrivateKeyPKCS8Base64(km.PrivateKeyPKCS8Base64)
	if err != nil {
		t.Fatalf("priv: %v", err)
	}
	_, curvePub, err := curve25519KeyPairFromEd25519PrivateKey(priv)
	if err != nil {
		t.Fatalf("curve: %v", err)
	}
	msg := "hello-task-id"
	sealed, err := box.SealAnonymous(nil, []byte(msg), curvePub, nil)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	got, err := DecryptEncryptedTaskID(km.PrivateKeyPKCS8Base64, base64.StdEncoding.EncodeToString(sealed))
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if got != msg {
		t.Fatalf("got %q want %q", got, msg)
	}
}

func TestEnsureAgentTaskIDCacheAndInvalidate(t *testing.T) {
	ResetAgentTaskCacheForTest()
	defer ResetAgentTaskCacheForTest()

	km, err := GenerateAgentKeyMaterial()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	rec := &AgentIdentityRecord{
		AgentRuntimeID:        "rt-cache",
		PrivateKeyPKCS8Base64: km.PrivateKeyPKCS8Base64,
		AccountID:             "acc",
	}
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_ = json.NewEncoder(w).Encode(map[string]string{"task_id": "cached-task"})
	}))
	defer srv.Close()

	key := AgentTaskCacheKey("auth-1", rec.AgentRuntimeID)
	a, err := EnsureAgentTaskIDWithBaseURL(context.Background(), srv.Client(), srv.URL, key, rec)
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	b, err := EnsureAgentTaskIDWithBaseURL(context.Background(), srv.Client(), srv.URL, key, rec)
	if err != nil {
		t.Fatalf("ensure second: %v", err)
	}
	if a != b || a != "cached-task" {
		t.Fatalf("cache miss: %q %q", a, b)
	}
	if atomic.LoadInt32(&hits) != 1 {
		t.Fatalf("expected 1 register call, got %d", hits)
	}
	InvalidateAgentTaskID(key)
	c, err := EnsureAgentTaskIDWithBaseURL(context.Background(), srv.Client(), srv.URL, key, rec)
	if err != nil {
		t.Fatalf("ensure after invalidate: %v", err)
	}
	if c != "cached-task" {
		t.Fatalf("task after invalidate: %q", c)
	}
	if atomic.LoadInt32(&hits) != 2 {
		t.Fatalf("expected 2 register calls after invalidate, got %d", hits)
	}
}

func TestEnsureAgentTaskIDSingleflight(t *testing.T) {
	ResetAgentTaskCacheForTest()
	defer ResetAgentTaskCacheForTest()

	km, err := GenerateAgentKeyMaterial()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	rec := &AgentIdentityRecord{
		AgentRuntimeID:        "rt-sf",
		PrivateKeyPKCS8Base64: km.PrivateKeyPKCS8Base64,
		AccountID:             "acc",
	}
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		time.Sleep(50 * time.Millisecond)
		_ = json.NewEncoder(w).Encode(map[string]string{"task_id": "sf-task"})
	}))
	defer srv.Close()

	key := AgentTaskCacheKey("auth-sf", "")
	const n = 8
	var wg sync.WaitGroup
	errs := make(chan error, n)
	results := make(chan string, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id, err := EnsureAgentTaskIDWithBaseURL(context.Background(), srv.Client(), srv.URL, key, rec)
			if err != nil {
				errs <- err
				return
			}
			results <- id
		}()
	}
	wg.Wait()
	close(errs)
	close(results)
	for err := range errs {
		t.Fatalf("ensure: %v", err)
	}
	for id := range results {
		if id != "sf-task" {
			t.Fatalf("task id: %q", id)
		}
	}
	if atomic.LoadInt32(&hits) != 1 {
		t.Fatalf("singleflight failed: hits=%d", hits)
	}
}

func TestRegisterAgentIdentityBearer(t *testing.T) {
	km, err := GenerateAgentKeyMaterial()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		if r.Header.Get("X-OpenAI-Fedramp") != "true" {
			t.Errorf("expected fedramp header")
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"agent_runtime_id": "new-rt"})
	}))
	defer srv.Close()

	rt, err := RegisterAgentIdentity(context.Background(), srv.Client(), srv.URL, "session-token", true, km, DefaultAgentBillOfMaterials(), nil)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if rt != "new-rt" {
		t.Fatalf("runtime: %q", rt)
	}
	if gotAuth != "Bearer session-token" {
		t.Fatalf("auth header: %q", gotAuth)
	}
}

func TestAgentCredentialFileName(t *testing.T) {
	tests := []struct {
		name          string
		email         string
		planType      string
		hashAccountID string
		want          string
	}{
		{
			name:          "with hash and plan",
			email:         "user@example.com",
			planType:      "plus",
			hashAccountID: "abc12345",
			want:          "codex-agent-abc12345-user@example.com-plus.json",
		},
		{
			name:          "without plan",
			email:         "user@example.com",
			planType:      "",
			hashAccountID: "abc12345",
			want:          "codex-agent-abc12345-user@example.com.json",
		},
		{
			name:          "email only",
			email:         "user@example.com",
			planType:      "team",
			hashAccountID: "",
			want:          "codex-agent-user@example.com-team.json",
		},
		{
			name:          "empty email uses unknown",
			email:         "",
			planType:      "",
			hashAccountID: "",
			want:          "codex-agent-unknown.json",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := AgentCredentialFileName(tt.email, tt.planType, tt.hashAccountID)
			if got != tt.want {
				t.Fatalf("AgentCredentialFileName() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDomainSeparatedKeyDerivationUsesContext(t *testing.T) {
	// Ensure derivation domain string is mixed into the seed (not plain SHA512 of material).
	material := make([]byte, agentIdentityKeySeedBytes)
	for i := range material {
		material[i] = 7
	}
	// Seed as used by our implementation.
	h := sha512.New()
	_, _ = h.Write([]byte(agentIdentityKeyDerivationCtx))
	_, _ = h.Write(material)
	wantSeed := h.Sum(nil)[:32]

	// Without domain would differ.
	plain := sha512.Sum512(material)
	if string(plain[:32]) == string(wantSeed) {
		t.Fatalf("domain separation should change seed")
	}
	km, err := generateAgentKeyMaterialFromSeed(material)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	priv, err := signingKeyFromPrivateKeyPKCS8Base64(km.PrivateKeyPKCS8Base64)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if string(priv.Seed()) != string(wantSeed) {
		t.Fatalf("derived seed mismatch")
	}
}

func TestBuildFlatAgentIdentityMetadata(t *testing.T) {
	rec := &AgentIdentityRecord{
		AgentRuntimeID:          "rt",
		PrivateKeyPKCS8Base64:   "pk",
		AccountID:               "acc",
		ChatGPTUserID:           "u",
		Email:                   "e@x.com",
		PlanType:                "plus",
		ChatGPTAccountIsFedRAMP: true,
	}
	meta := BuildFlatAgentIdentityMetadata(rec)
	if meta["auth_mode"] != AgentAuthMode || meta["type"] != "codex" {
		t.Fatalf("meta: %+v", meta)
	}
	if meta["chatgpt_account_is_fedramp"] != true {
		t.Fatalf("fedramp: %v", meta["chatgpt_account_is_fedramp"])
	}
}
