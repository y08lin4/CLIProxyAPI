package codex

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"golang.org/x/sync/singleflight"
)

// agentTaskCache stores process-local task IDs for agent identities.
// Task IDs must not be persisted to auth files.
type agentTaskCache struct {
	mu    sync.RWMutex
	tasks map[string]string
	group singleflight.Group
}

var globalAgentTaskCache = &agentTaskCache{
	tasks: make(map[string]string),
}

// AgentTaskCacheKey returns the cache key for an auth entry.
// Prefer a stable auth ID; fall back to agent_runtime_id.
func AgentTaskCacheKey(authID, agentRuntimeID string) string {
	authID = strings.TrimSpace(authID)
	if authID != "" {
		return "id:" + authID
	}
	agentRuntimeID = strings.TrimSpace(agentRuntimeID)
	if agentRuntimeID != "" {
		return "runtime:" + agentRuntimeID
	}
	return ""
}

// EnsureAgentTaskID returns a cached task id or registers a new one (singleflight-protected).
func EnsureAgentTaskID(ctx context.Context, client *http.Client, authKey string, rec *AgentIdentityRecord) (string, error) {
	return EnsureAgentTaskIDWithBaseURL(ctx, client, ProdAgentIdentityAuthAPIBaseURL(), authKey, rec)
}

// EnsureAgentTaskIDWithBaseURL is like EnsureAgentTaskID but allows overriding the authapi base URL (tests).
func EnsureAgentTaskIDWithBaseURL(ctx context.Context, client *http.Client, authAPIBaseURL, authKey string, rec *AgentIdentityRecord) (string, error) {
	if rec == nil {
		return "", fmt.Errorf("codex agent identity: record is required")
	}
	key := strings.TrimSpace(authKey)
	if key == "" {
		key = AgentTaskCacheKey("", rec.AgentRuntimeID)
	}
	if key == "" {
		return "", fmt.Errorf("codex agent identity: cache key is required")
	}

	if taskID := globalAgentTaskCache.get(key); taskID != "" {
		return taskID, nil
	}

	v, err, _ := globalAgentTaskCache.group.Do(key, func() (any, error) {
		// Double-check after winning the singleflight.
		if taskID := globalAgentTaskCache.get(key); taskID != "" {
			return taskID, nil
		}
		taskID, err := RegisterAgentTask(ctx, client, authAPIBaseURL, rec)
		if err != nil {
			return "", err
		}
		globalAgentTaskCache.set(key, taskID)
		return taskID, nil
	})
	if err != nil {
		return "", err
	}
	taskID, _ := v.(string)
	if strings.TrimSpace(taskID) == "" {
		return "", fmt.Errorf("codex agent identity: empty task id")
	}
	return taskID, nil
}

// InvalidateAgentTaskID drops a cached task id so the next request re-registers.
func InvalidateAgentTaskID(authKey string) {
	authKey = strings.TrimSpace(authKey)
	if authKey == "" {
		return
	}
	globalAgentTaskCache.delete(authKey)
}

// InvalidateAgentTaskIDForAuth invalidates by auth ID and/or runtime ID.
func InvalidateAgentTaskIDForAuth(authID, agentRuntimeID string) {
	if k := AgentTaskCacheKey(authID, ""); k != "" {
		InvalidateAgentTaskID(k)
	}
	if k := AgentTaskCacheKey("", agentRuntimeID); k != "" {
		InvalidateAgentTaskID(k)
	}
	// Also invalidate combined form if callers used auth ID with runtime fallback style.
	if k := AgentTaskCacheKey(authID, agentRuntimeID); k != "" {
		InvalidateAgentTaskID(k)
	}
}

// ResetAgentTaskCacheForTest clears the process-local cache (tests only).
func ResetAgentTaskCacheForTest() {
	globalAgentTaskCache.mu.Lock()
	globalAgentTaskCache.tasks = make(map[string]string)
	globalAgentTaskCache.mu.Unlock()
}

func (c *agentTaskCache) get(key string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.tasks[key]
}

func (c *agentTaskCache) set(key, taskID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tasks == nil {
		c.tasks = make(map[string]string)
	}
	c.tasks[key] = taskID
}

func (c *agentTaskCache) delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.tasks, key)
}
