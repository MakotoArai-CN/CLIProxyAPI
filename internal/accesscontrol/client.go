package accesscontrol

import (
	"strings"
	"sync"
	"time"
)

// Known AI coding client presets: (id, display label, UA keywords to match).
var clientPresets = []struct {
	ID       string
	Label    string
	Keywords []string
}{
	{"claude-code", "Claude Code", []string{"claude-code", "claude code"}},
	{"codex-cli", "Codex CLI", []string{"codex"}},
	{"chatgpt", "ChatGPT", []string{"chatgpt"}},
	{"opencode", "OpenCode", []string{"opencode"}},
	{"continue", "Continue", []string{"continue"}},
	{"cursor", "Cursor", []string{"cursor"}},
	{"aider", "Aider", []string{"aider"}},
	{"windsurf", "Windsurf", []string{"windsurf"}},
	{"cline", "Cline", []string{"cline"}},
	{"copilot", "GitHub Copilot", []string{"copilot"}},
	{"roo-code", "Roo Code", []string{"roo-code", "roo code"}},
	{"augment", "Augment", []string{"augment"}},
	{"openhands", "OpenHands", []string{"openhands"}},
	{"amazon-q", "Amazon Q", []string{"amazon q"}},
	{"gemini-code", "Gemini Code Assist", []string{"gemini"}},
	{"zed", "Zed AI", []string{"zed"}},
}

// ClientEntry is one entry in the client whitelist.
type ClientEntry struct {
	ClientID  string    `json:"client_id"`
	Label     string    `json:"label"`
	Note      string    `json:"note,omitempty"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
}

// ClientWhitelistState is the full persisted state.
type ClientWhitelistState struct {
	Active  bool          `json:"active"`
	Entries []ClientEntry `json:"entries"`
}

// clientWhitelist manages the in-memory client whitelist.
type clientWhitelist struct {
	mu      sync.RWMutex
	active  bool
	entries map[string]ClientEntry // keyed by client_id
}

func newClientWhitelist() *clientWhitelist {
	return &clientWhitelist{entries: make(map[string]ClientEntry)}
}

func (cw *clientWhitelist) load(state ClientWhitelistState) {
	cw.mu.Lock()
	defer cw.mu.Unlock()
	cw.active = state.Active
	cw.entries = make(map[string]ClientEntry, len(state.Entries))
	for _, e := range state.Entries {
		cw.entries[e.ClientID] = e
	}
}

// DetectClient returns (clientID, label) from the request headers.
// Callers pass ua = User-Agent header, xpc = X-Proxy-Client header.
func DetectClient(ua, xpc string) (string, string) {
	xpc = strings.TrimSpace(strings.ToLower(xpc))
	if xpc != "" {
		return xpc, xpc
	}
	ua = strings.ToLower(ua)
	for _, p := range clientPresets {
		for _, kw := range p.Keywords {
			if strings.Contains(ua, kw) {
				return p.ID, p.Label
			}
		}
	}
	return "unknown", "Unknown"
}

// Check returns (allowed, clientID, label).
func (cw *clientWhitelist) Check(ua, xpc string) (bool, string, string) {
	id, label := DetectClient(ua, xpc)
	cw.mu.RLock()
	defer cw.mu.RUnlock()
	if !cw.active {
		return true, id, label
	}
	entry, ok := cw.entries[id]
	if !ok {
		return false, id, label
	}
	return entry.Enabled, id, entry.Label
}

func (cw *clientWhitelist) SetActive(active bool) {
	cw.mu.Lock()
	cw.active = active
	cw.mu.Unlock()
}

func (cw *clientWhitelist) Upsert(e ClientEntry) {
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now()
	}
	cw.mu.Lock()
	if existing, ok := cw.entries[e.ClientID]; ok {
		e.CreatedAt = existing.CreatedAt // preserve original creation time
	}
	cw.entries[e.ClientID] = e
	cw.mu.Unlock()
}

func (cw *clientWhitelist) Remove(clientID string) bool {
	cw.mu.Lock()
	defer cw.mu.Unlock()
	_, ok := cw.entries[clientID]
	if ok {
		delete(cw.entries, clientID)
	}
	return ok
}

func (cw *clientWhitelist) State() ClientWhitelistState {
	cw.mu.RLock()
	defer cw.mu.RUnlock()
	entries := make([]ClientEntry, 0, len(cw.entries))
	for _, e := range cw.entries {
		entries = append(entries, e)
	}
	return ClientWhitelistState{Active: cw.active, Entries: entries}
}

// Presets returns the built-in known client list.
func ClientPresets() []struct{ ID, Label string } {
	out := make([]struct{ ID, Label string }, len(clientPresets))
	for i, p := range clientPresets {
		out[i] = struct{ ID, Label string }{p.ID, p.Label}
	}
	return out
}
