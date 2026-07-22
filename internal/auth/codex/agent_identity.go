package codex

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

// AgentAuthMode is the canonical auth_mode value for Codex Agent Identity files.
const AgentAuthMode = "agent_identity"

const (
	agentIdentityKeySeedBytes       = 64
	agentIdentityKeyDerivationCtx   = "codex-agent-identity-ed25519-v1"
	prodAgentIdentityAuthAPIBaseURL = "https://auth.openai.com/api/accounts"
	agentRegistrationTimeout        = 15 * time.Second
	agentTaskRegistrationTimeout    = 30 * time.Second
	defaultAgentHarnessID           = "codex-cli"
	defaultAgentVersion             = "cli-proxy-api"
	defaultAgentCapability          = "responsesapi"
)

// AgentIdentityRecord is the durable signing material for a registered agent identity.
// Task IDs are process-local and never stored here.
type AgentIdentityRecord struct {
	AgentRuntimeID          string
	PrivateKeyPKCS8Base64   string
	AccountID               string
	ChatGPTUserID           string
	Email                   string
	PlanType                string
	ChatGPTAccountIsFedRAMP bool
}

// AgentBillOfMaterials describes the registering client for agent registration.
type AgentBillOfMaterials struct {
	AgentVersion    string `json:"agent_version"`
	AgentHarnessID  string `json:"agent_harness_id"`
	RunningLocation string `json:"running_location"`
}

// GeneratedAgentKeyMaterial is freshly generated Ed25519 key material for registration.
type GeneratedAgentKeyMaterial struct {
	PrivateKeyPKCS8Base64 string
	PublicKeySSH          string
}

type agentAssertionEnvelope struct {
	AgentRuntimeID string `json:"agent_runtime_id"`
	TaskID         string `json:"task_id"`
	Timestamp      string `json:"timestamp"`
	Signature      string `json:"signature"`
}

type registerTaskRequest struct {
	Timestamp string `json:"timestamp"`
	Signature string `json:"signature"`
}

type registerTaskResponse struct {
	TaskID               string `json:"task_id"`
	TaskIDCamel          string `json:"taskId"`
	EncryptedTaskID      string `json:"encrypted_task_id"`
	EncryptedTaskIDCamel string `json:"encryptedTaskId"`
}

type registerAgentRequest struct {
	ABOM           AgentBillOfMaterials `json:"abom"`
	AgentPublicKey string               `json:"agent_public_key"`
	Capabilities   []string             `json:"capabilities"`
	TTL            *uint64              `json:"ttl"`
}

type registerAgentResponse struct {
	AgentRuntimeID string `json:"agent_runtime_id"`
}

// DefaultAgentBillOfMaterials returns a CPA-side ABOM for agent registration.
func DefaultAgentBillOfMaterials() AgentBillOfMaterials {
	return AgentBillOfMaterials{
		AgentVersion:    defaultAgentVersion,
		AgentHarnessID:  defaultAgentHarnessID,
		RunningLocation: defaultAgentHarnessID + "-proxy",
	}
}

// ProdAgentIdentityAuthAPIBaseURL returns the production authapi base URL.
func ProdAgentIdentityAuthAPIBaseURL() string {
	return prodAgentIdentityAuthAPIBaseURL
}

// IsAgentIdentityMetadata reports whether metadata represents an Agent Identity auth.
func IsAgentIdentityMetadata(meta map[string]any) bool {
	if meta == nil {
		return false
	}
	mode := strings.ToLower(strings.TrimSpace(metaString(meta, "auth_mode")))
	if mode == "" {
		mode = strings.ToLower(strings.TrimSpace(metaString(meta, "auth-mode")))
	}
	if mode == AgentAuthMode {
		return true
	}
	if _, ok := meta["agent_identity"]; ok {
		return true
	}
	if strings.TrimSpace(metaString(meta, "agent_runtime_id")) != "" &&
		strings.TrimSpace(metaString(meta, "agent_private_key")) != "" {
		return true
	}
	return false
}

// NormalizeAgentIdentityMetadata flattens nested / JWT agent identity forms into
// the canonical CPA flat shape. Non-agent metadata is returned unchanged.
func NormalizeAgentIdentityMetadata(raw map[string]any) (map[string]any, error) {
	if raw == nil {
		return nil, nil
	}
	if !IsAgentIdentityMetadata(raw) {
		return cloneStringAnyMap(raw), nil
	}

	// Start from a shallow copy so we can rewrite without mutating the caller.
	out := cloneStringAnyMap(raw)

	// Nested object form: auth_mode + agent_identity: { ... }
	if nested, ok := out["agent_identity"]; ok && nested != nil {
		switch v := nested.(type) {
		case map[string]any:
			mergeAgentIdentityFields(out, v)
			delete(out, "agent_identity")
		case string:
			// JWT string form — decode payload without JWKS verification (MVP).
			claims, err := decodeAgentIdentityJWTPayload(v)
			if err != nil {
				return nil, fmt.Errorf("codex agent identity: decode nested JWT: %w", err)
			}
			mergeAgentIdentityFields(out, claims)
			delete(out, "agent_identity")
		default:
			return nil, fmt.Errorf("codex agent identity: unsupported agent_identity type %T", nested)
		}
	}

	// Top-level JWT-ish: agent_identity fields already flat, or only auth_mode present with jwt-like private key already set.
	// Ensure auth_mode and type are canonical.
	out["auth_mode"] = AgentAuthMode
	if t := strings.TrimSpace(metaString(out, "type")); t == "" {
		out["type"] = "codex"
	}

	// Validate required fields after normalize.
	if strings.TrimSpace(metaString(out, "agent_runtime_id")) == "" {
		return nil, fmt.Errorf("codex agent identity: agent_runtime_id is required")
	}
	if strings.TrimSpace(metaString(out, "agent_private_key")) == "" {
		return nil, fmt.Errorf("codex agent identity: agent_private_key is required")
	}
	if strings.TrimSpace(metaString(out, "account_id")) == "" {
		// Accept chatgpt_account_id alias.
		if aid := strings.TrimSpace(metaString(out, "chatgpt_account_id")); aid != "" {
			out["account_id"] = aid
		}
	}
	if strings.TrimSpace(metaString(out, "account_id")) == "" {
		return nil, fmt.Errorf("codex agent identity: account_id is required")
	}

	// Drop OAuth tokens that are not needed for agent identity call path.
	// Keep them if present is harmless for storage, but Refresh must no-op;
	// we leave them only when explicitly present from partial bootstrap — prefer clean flat.
	// Do not force-delete so upload of mixed files remains inspectable; executor ignores them.

	// Ensure private key is parseable.
	if _, err := signingKeyFromPrivateKeyPKCS8Base64(metaString(out, "agent_private_key")); err != nil {
		return nil, fmt.Errorf("codex agent identity: invalid agent_private_key: %w", err)
	}

	return out, nil
}

// AgentIdentityFromMetadata extracts a validated AgentIdentityRecord from metadata.
func AgentIdentityFromMetadata(meta map[string]any) (*AgentIdentityRecord, error) {
	normalized, err := NormalizeAgentIdentityMetadata(meta)
	if err != nil {
		return nil, err
	}
	if normalized == nil || !IsAgentIdentityMetadata(normalized) {
		return nil, fmt.Errorf("codex agent identity: metadata is not agent identity")
	}
	rec := &AgentIdentityRecord{
		AgentRuntimeID:          strings.TrimSpace(metaString(normalized, "agent_runtime_id")),
		PrivateKeyPKCS8Base64:   strings.TrimSpace(metaString(normalized, "agent_private_key")),
		AccountID:               strings.TrimSpace(metaString(normalized, "account_id")),
		ChatGPTUserID:           strings.TrimSpace(metaString(normalized, "chatgpt_user_id")),
		Email:                   strings.TrimSpace(metaString(normalized, "email")),
		PlanType:                strings.TrimSpace(metaString(normalized, "plan_type")),
		ChatGPTAccountIsFedRAMP: metaBool(normalized, "chatgpt_account_is_fedramp"),
	}
	if rec.AgentRuntimeID == "" || rec.PrivateKeyPKCS8Base64 == "" || rec.AccountID == "" {
		return nil, fmt.Errorf("codex agent identity: incomplete record")
	}
	return rec, nil
}

// GenerateAgentKeyMaterial generates domain-separated Ed25519 key material matching Codex CLI.
func GenerateAgentKeyMaterial() (*GeneratedAgentKeyMaterial, error) {
	material := make([]byte, agentIdentityKeySeedBytes)
	if _, err := io.ReadFull(rand.Reader, material); err != nil {
		return nil, fmt.Errorf("codex agent identity: generate seed material: %w", err)
	}
	return generateAgentKeyMaterialFromSeed(material)
}

// generateAgentKeyMaterialFromSeed is exposed for deterministic tests.
func generateAgentKeyMaterialFromSeed(seedMaterial []byte) (*GeneratedAgentKeyMaterial, error) {
	if len(seedMaterial) != agentIdentityKeySeedBytes {
		return nil, fmt.Errorf("codex agent identity: seed material must be %d bytes", agentIdentityKeySeedBytes)
	}
	h := sha512.New()
	_, _ = h.Write([]byte(agentIdentityKeyDerivationCtx))
	_, _ = h.Write(seedMaterial)
	digest := h.Sum(nil)
	seed := digest[:32]
	priv := ed25519.NewKeyFromSeed(seed)
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("codex agent identity: marshal PKCS#8: %w", err)
	}
	return &GeneratedAgentKeyMaterial{
		PrivateKeyPKCS8Base64: base64.StdEncoding.EncodeToString(pkcs8),
		PublicKeySSH:          encodeSSHEd25519PublicKey(priv.Public().(ed25519.PublicKey)),
	}, nil
}

// PublicKeySSHFromPrivateKeyPKCS8Base64 derives the OpenSSH public key string from a stored private key.
func PublicKeySSHFromPrivateKeyPKCS8Base64(privateKeyPKCS8Base64 string) (string, error) {
	priv, err := signingKeyFromPrivateKeyPKCS8Base64(privateKeyPKCS8Base64)
	if err != nil {
		return "", err
	}
	return encodeSSHEd25519PublicKey(priv.Public().(ed25519.PublicKey)), nil
}

// RegisterAgentIdentity registers a new agent runtime with OpenAI authapi using a session access token.
// Timeouts are intentional: this is credential acquisition.
func RegisterAgentIdentity(ctx context.Context, client *http.Client, authAPIBaseURL, accessToken string, isFedRAMP bool, keyMaterial *GeneratedAgentKeyMaterial, abom AgentBillOfMaterials, capabilities []string) (string, error) {
	if client == nil {
		client = http.DefaultClient
	}
	if keyMaterial == nil {
		return "", fmt.Errorf("codex agent identity: key material is required")
	}
	accessToken = strings.TrimSpace(accessToken)
	if accessToken == "" {
		return "", fmt.Errorf("codex agent identity: access_token is required")
	}
	base := strings.TrimRight(strings.TrimSpace(authAPIBaseURL), "/")
	if base == "" {
		base = prodAgentIdentityAuthAPIBaseURL
	}
	if strings.TrimSpace(abom.AgentVersion) == "" {
		abom = DefaultAgentBillOfMaterials()
	}
	if len(capabilities) == 0 {
		capabilities = []string{defaultAgentCapability}
	}
	body := registerAgentRequest{
		ABOM:           abom,
		AgentPublicKey: keyMaterial.PublicKeySSH,
		Capabilities:   capabilities,
		TTL:            nil,
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("codex agent identity: marshal register body: %w", err)
	}
	url := base + "/v1/agent/register"
	reqCtx, cancel := context.WithTimeout(ctx, agentRegistrationTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return "", fmt.Errorf("codex agent identity: create register request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)
	if isFedRAMP {
		req.Header.Set("X-OpenAI-Fedramp", "true")
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("codex agent identity: register request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("codex agent identity: register failed status %d: %s", resp.StatusCode, truncateForError(string(respBody), 512))
	}
	var parsed registerAgentResponse
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return "", fmt.Errorf("codex agent identity: decode register response: %w", err)
	}
	runtimeID := strings.TrimSpace(parsed.AgentRuntimeID)
	if runtimeID == "" {
		return "", fmt.Errorf("codex agent identity: register response missing agent_runtime_id")
	}
	return runtimeID, nil
}

// RegisterAgentTask registers a process-local task for the agent identity.
// Official protocol: no Bearer token on this request.
// Timeout is intentional (credential acquisition).
func RegisterAgentTask(ctx context.Context, client *http.Client, authAPIBaseURL string, rec *AgentIdentityRecord) (string, error) {
	if client == nil {
		client = http.DefaultClient
	}
	if rec == nil {
		return "", fmt.Errorf("codex agent identity: record is required")
	}
	base := strings.TrimRight(strings.TrimSpace(authAPIBaseURL), "/")
	if base == "" {
		base = prodAgentIdentityAuthAPIBaseURL
	}
	timestamp := time.Now().UTC().Format(time.RFC3339)
	// Official uses RFC3339 with seconds and Z suffix (chrono SecondsFormat::Secs, true).
	timestamp = normalizeRFC3339Z(timestamp)
	sig, err := SignTaskRegistrationPayload(rec, timestamp)
	if err != nil {
		return "", err
	}
	body := registerTaskRequest{Timestamp: timestamp, Signature: sig}
	payload, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("codex agent identity: marshal task register body: %w", err)
	}
	url := fmt.Sprintf("%s/v1/agent/%s/task/register", base, rec.AgentRuntimeID)
	reqCtx, cancel := context.WithTimeout(ctx, agentTaskRegistrationTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return "", fmt.Errorf("codex agent identity: create task register request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	// Intentionally no Authorization header (official protocol).
	if rec.ChatGPTAccountIsFedRAMP {
		req.Header.Set("X-OpenAI-Fedramp", "true")
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("codex agent identity: task register request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("codex agent identity: task register failed status %d: %s", resp.StatusCode, truncateForError(string(respBody), 512))
	}
	var parsed registerTaskResponse
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return "", fmt.Errorf("codex agent identity: decode task register response: %w", err)
	}
	if taskID := firstNonEmpty(parsed.TaskID, parsed.TaskIDCamel); taskID != "" {
		return taskID, nil
	}
	encrypted := firstNonEmpty(parsed.EncryptedTaskID, parsed.EncryptedTaskIDCamel)
	if encrypted == "" {
		return "", fmt.Errorf("codex agent identity: task register response omitted task id")
	}
	return DecryptEncryptedTaskID(rec.PrivateKeyPKCS8Base64, encrypted)
}

// SignTaskRegistrationPayload signs "{runtime_id}:{timestamp}" with the agent private key.
func SignTaskRegistrationPayload(rec *AgentIdentityRecord, timestamp string) (string, error) {
	if rec == nil {
		return "", fmt.Errorf("codex agent identity: record is required")
	}
	priv, err := signingKeyFromPrivateKeyPKCS8Base64(rec.PrivateKeyPKCS8Base64)
	if err != nil {
		return "", err
	}
	payload := rec.AgentRuntimeID + ":" + timestamp
	sig := ed25519.Sign(priv, []byte(payload))
	return base64.StdEncoding.EncodeToString(sig), nil
}

// AuthorizationHeaderForAgentTask builds "AgentAssertion <base64url JSON>" for a request.
func AuthorizationHeaderForAgentTask(rec *AgentIdentityRecord, taskID string) (string, error) {
	if rec == nil {
		return "", fmt.Errorf("codex agent identity: record is required")
	}
	taskID = strings.TrimSpace(taskID)
	if taskID == "" {
		return "", fmt.Errorf("codex agent identity: task_id is required")
	}
	timestamp := normalizeRFC3339Z(time.Now().UTC().Format(time.RFC3339))
	sig, err := signAgentAssertionPayload(rec, taskID, timestamp)
	if err != nil {
		return "", err
	}
	// BTreeMap key order: agent_runtime_id, signature, task_id, timestamp
	serialized, err := serializeAgentAssertion(rec.AgentRuntimeID, taskID, timestamp, sig)
	if err != nil {
		return "", err
	}
	return "AgentAssertion " + serialized, nil
}

// DecryptEncryptedTaskID decrypts an encrypted_task_id using the Curve25519 key derived from the Ed25519 seed.
func DecryptEncryptedTaskID(privateKeyPKCS8Base64, encryptedB64 string) (string, error) {
	priv, err := signingKeyFromPrivateKeyPKCS8Base64(privateKeyPKCS8Base64)
	if err != nil {
		return "", err
	}
	ciphertext, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encryptedB64))
	if err != nil {
		return "", fmt.Errorf("codex agent identity: encrypted task id is not valid base64: %w", err)
	}
	curvePriv, curvePub, err := curve25519KeyPairFromEd25519PrivateKey(priv)
	if err != nil {
		return "", err
	}
	opened, ok := box.OpenAnonymous(nil, ciphertext, curvePub, curvePriv)
	if !ok {
		return "", fmt.Errorf("codex agent identity: failed to decrypt encrypted task id")
	}
	if !json.Valid(opened) && !isPrintableUTF8(opened) {
		// task ids are plain UTF-8 strings; still accept if UTF-8.
	}
	return string(opened), nil
}

func signAgentAssertionPayload(rec *AgentIdentityRecord, taskID, timestamp string) (string, error) {
	priv, err := signingKeyFromPrivateKeyPKCS8Base64(rec.PrivateKeyPKCS8Base64)
	if err != nil {
		return "", err
	}
	payload := rec.AgentRuntimeID + ":" + taskID + ":" + timestamp
	sig := ed25519.Sign(priv, []byte(payload))
	return base64.StdEncoding.EncodeToString(sig), nil
}

// serializeAgentAssertion encodes the envelope as base64url(no pad) of stable-key-order JSON.
func serializeAgentAssertion(runtimeID, taskID, timestamp, signature string) (string, error) {
	// Build JSON with BTreeMap key order: agent_runtime_id, signature, task_id, timestamp.
	var buf bytes.Buffer
	buf.WriteByte('{')
	writeJSONStringField(&buf, "agent_runtime_id", runtimeID, false)
	writeJSONStringField(&buf, "signature", signature, false)
	writeJSONStringField(&buf, "task_id", taskID, false)
	writeJSONStringField(&buf, "timestamp", timestamp, true)
	buf.WriteByte('}')
	return base64.RawURLEncoding.EncodeToString(buf.Bytes()), nil
}

func writeJSONStringField(buf *bytes.Buffer, key, value string, last bool) {
	// Use encoding/json for proper string escaping.
	kb, _ := json.Marshal(key)
	vb, _ := json.Marshal(value)
	buf.Write(kb)
	buf.WriteByte(':')
	buf.Write(vb)
	if !last {
		buf.WriteByte(',')
	}
}

func signingKeyFromPrivateKeyPKCS8Base64(privateKeyPKCS8Base64 string) (ed25519.PrivateKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(privateKeyPKCS8Base64))
	if err != nil {
		return nil, fmt.Errorf("codex agent identity: private key is not valid base64: %w", err)
	}
	key, err := x509.ParsePKCS8PrivateKey(raw)
	if err != nil {
		return nil, fmt.Errorf("codex agent identity: private key is not valid PKCS#8: %w", err)
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("codex agent identity: private key is not Ed25519")
	}
	return priv, nil
}

func encodeSSHEd25519PublicKey(pub ed25519.PublicKey) string {
	var blob bytes.Buffer
	appendSSHString(&blob, []byte("ssh-ed25519"))
	appendSSHString(&blob, pub)
	return "ssh-ed25519 " + base64.StdEncoding.EncodeToString(blob.Bytes())
}

func appendSSHString(buf *bytes.Buffer, value []byte) {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(value)))
	buf.Write(lenBuf[:])
	buf.Write(value)
}

// curve25519KeyPairFromEd25519PrivateKey derives a clamped Curve25519 key pair from the Ed25519 seed,
// matching crypto_box / libsodium conversion used by official Codex.
func curve25519KeyPairFromEd25519PrivateKey(priv ed25519.PrivateKey) (privateKey, publicKey *[32]byte, err error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, nil, fmt.Errorf("codex agent identity: invalid ed25519 private key length")
	}
	// Seed is the first 32 bytes of the Go ed25519.PrivateKey.
	seed := priv.Seed()
	digest := sha512.Sum512(seed)
	var secret [32]byte
	copy(secret[:], digest[:32])
	secret[0] &= 248
	secret[31] &= 127
	secret[31] |= 64
	var pub [32]byte
	curve25519.ScalarBaseMult(&pub, &secret)
	return &secret, &pub, nil
}

func decodeAgentIdentityJWTPayload(jwt string) (map[string]any, error) {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid agent identity JWT format")
	}
	payload, err := base64URLDecode(parts[1])
	if err != nil {
		return nil, fmt.Errorf("agent identity JWT payload is not valid base64url: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("agent identity JWT payload is not valid JSON: %w", err)
	}
	return claims, nil
}

func mergeAgentIdentityFields(dst, src map[string]any) {
	if dst == nil || src == nil {
		return
	}
	// Prefer nested/src values for identity fields.
	keys := []string{
		"agent_runtime_id",
		"agent_private_key",
		"account_id",
		"chatgpt_account_id",
		"chatgpt_user_id",
		"email",
		"plan_type",
		"chatgpt_account_is_fedramp",
	}
	for _, k := range keys {
		if v, ok := src[k]; ok && v != nil {
			// plan_type may be a structured value in some JWTs; stringify known forms.
			if k == "plan_type" {
				dst[k] = stringifyPlanType(v)
				continue
			}
			dst[k] = v
		}
	}
	// Map chatgpt_account_id → account_id if account_id still empty.
	if strings.TrimSpace(metaString(dst, "account_id")) == "" {
		if aid := strings.TrimSpace(metaString(src, "chatgpt_account_id")); aid != "" {
			dst["account_id"] = aid
		}
		if aid := strings.TrimSpace(metaString(src, "account_id")); aid != "" {
			dst["account_id"] = aid
		}
	}
	if mode := strings.TrimSpace(metaString(src, "auth_mode")); mode != "" {
		dst["auth_mode"] = mode
	}
}

func stringifyPlanType(v any) string {
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case map[string]any:
		// e.g. {"known":"pro"} or similar — take first string value.
		for _, candidate := range []string{"known", "value", "plan", "name"} {
			if s, ok := t[candidate].(string); ok && strings.TrimSpace(s) != "" {
				return strings.TrimSpace(s)
			}
		}
		b, err := json.Marshal(t)
		if err == nil {
			return string(b)
		}
	}
	return strings.TrimSpace(fmt.Sprint(v))
}

func metaString(meta map[string]any, key string) string {
	if meta == nil {
		return ""
	}
	v, ok := meta[key]
	if !ok || v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	default:
		return fmt.Sprint(t)
	}
}

func metaBool(meta map[string]any, key string) bool {
	if meta == nil {
		return false
	}
	v, ok := meta[key]
	if !ok || v == nil {
		return false
	}
	switch t := v.(type) {
	case bool:
		return t
	case string:
		switch strings.ToLower(strings.TrimSpace(t)) {
		case "1", "true", "yes", "y", "on":
			return true
		}
	case float64:
		return t != 0
	case json.Number:
		i, err := t.Int64()
		return err == nil && i != 0
	}
	return false
}

func cloneStringAnyMap(in map[string]any) map[string]any {
	if in == nil {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func truncateForError(s string, max int) string {
	s = strings.TrimSpace(s)
	if max <= 0 || len(s) <= max {
		return s
	}
	// Prefer rune-safe cut for display.
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	return string(runes[:max]) + "..."
}

func normalizeRFC3339Z(ts string) string {
	ts = strings.TrimSpace(ts)
	if ts == "" {
		return time.Now().UTC().Format("2006-01-02T15:04:05Z")
	}
	// Prefer exact Zulu seconds form.
	if t, err := time.Parse(time.RFC3339, ts); err == nil {
		return t.UTC().Format("2006-01-02T15:04:05Z")
	}
	if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
		return t.UTC().Format("2006-01-02T15:04:05Z")
	}
	return ts
}

func isPrintableUTF8(b []byte) bool {
	return json.Valid(append(append([]byte(`"`), bytes.ReplaceAll(b, []byte(`"`), []byte(`\"`))...), '"'))
}

// BuildFlatAgentIdentityMetadata builds the canonical flat auth file map for persistence.
func BuildFlatAgentIdentityMetadata(rec *AgentIdentityRecord) map[string]any {
	if rec == nil {
		return nil
	}
	meta := map[string]any{
		"type":                       "codex",
		"auth_mode":                  AgentAuthMode,
		"agent_runtime_id":           rec.AgentRuntimeID,
		"agent_private_key":          rec.PrivateKeyPKCS8Base64,
		"account_id":                 rec.AccountID,
		"chatgpt_user_id":            rec.ChatGPTUserID,
		"email":                      rec.Email,
		"plan_type":                  rec.PlanType,
		"chatgpt_account_is_fedramp": rec.ChatGPTAccountIsFedRAMP,
		"disabled":                   false,
	}
	return meta
}
