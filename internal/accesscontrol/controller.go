package accesscontrol

import (
	"fmt"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	ActionAllow   = "allow"
	ActionDeny    = "deny"
	ActionRoute   = "route"
	ActionChannel = "channel"

	StatusNormal         = "normal"
	StatusBanned         = "banned"
	StatusRiskControlled = "risk_controlled"

	PolicyInvalidModel  = "invalid_model"
	PolicyInvalidAPIKey = "invalid_apikey"

	cleanupInterval = 10 * time.Minute
)

type ModelPolicy struct {
	Model     string    `json:"model"`
	Action    string    `json:"action"`
	RouteTo   string    `json:"route_to,omitempty"`
	ChannelTo string    `json:"channel_to,omitempty"`
	Reason    string    `json:"reason,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

type IPRecord struct {
	IP        string     `json:"ip"`
	Status    string     `json:"status"`
	Reason    string     `json:"reason,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

type AutoPolicy struct {
	Type      string `json:"type"`
	Threshold int    `json:"threshold"`
	Window    int    `json:"window_seconds"`
	Action    string `json:"action"`
	Duration  int    `json:"duration_seconds"`
}

type IPCheckResult struct {
	Blocked bool
	Status  string
	Reason  string
}

type ModelCheckResult struct {
	Action    string
	RouteTo   string
	ChannelTo string
}

type Controller struct {
	mu            sync.RWMutex
	modelPolicies map[string]ModelPolicy
	ipRecords     map[string]IPRecord
	autoPolicies  map[string]AutoPolicy

	invalidModelWindow  *slidingWindow
	invalidAPIKeyWindow *slidingWindow

	store  *store
	stopCh chan struct{}
}

func NewController(dbPath string) (*Controller, error) {
	st, err := openStore(dbPath)
	if err != nil {
		return nil, err
	}

	c := &Controller{
		modelPolicies:       make(map[string]ModelPolicy),
		ipRecords:           make(map[string]IPRecord),
		autoPolicies:        make(map[string]AutoPolicy),
		invalidModelWindow:  newSlidingWindow(),
		invalidAPIKeyWindow: newSlidingWindow(),
		store:               st,
		stopCh:              make(chan struct{}),
	}

	if err = c.loadFromStore(); err != nil {
		_ = st.close()
		return nil, fmt.Errorf("access control: load state: %w", err)
	}

	go c.cleanupLoop()
	return c, nil
}

func (c *Controller) loadFromStore() error {
	policies, err := c.store.loadModelPolicies()
	if err != nil {
		return err
	}
	for _, p := range policies {
		c.modelPolicies[p.Model] = p
	}

	ips, err := c.store.loadIPRecords()
	if err != nil {
		return err
	}
	for _, r := range ips {
		c.ipRecords[r.IP] = r
	}

	autos, err := c.store.loadAutoPolicies()
	if err != nil {
		return err
	}
	for _, a := range autos {
		c.autoPolicies[a.Type] = a
	}

	log.Infof("access control: loaded %d model policies, %d IP records, %d auto-policies",
		len(c.modelPolicies), len(c.ipRecords), len(c.autoPolicies))
	return nil
}

func (c *Controller) Close() error {
	close(c.stopCh)
	if c.store != nil {
		return c.store.close()
	}
	return nil
}

// CheckIP returns the block status for the given IP.
func (c *Controller) CheckIP(ip string) IPCheckResult {
	c.mu.RLock()
	r, ok := c.ipRecords[ip]
	c.mu.RUnlock()
	if !ok {
		return IPCheckResult{}
	}
	switch r.Status {
	case StatusBanned:
		if r.ExpiresAt != nil && time.Now().After(*r.ExpiresAt) {
			go c.removeExpiredIP(ip)
			return IPCheckResult{}
		}
		return IPCheckResult{Blocked: true, Status: StatusBanned, Reason: r.Reason}
	case StatusRiskControlled:
		if r.ExpiresAt != nil && time.Now().After(*r.ExpiresAt) {
			go c.removeExpiredIP(ip)
			return IPCheckResult{}
		}
		return IPCheckResult{Blocked: true, Status: StatusRiskControlled, Reason: r.Reason}
	}
	return IPCheckResult{}
}

func (c *Controller) removeExpiredIP(ip string) {
	c.mu.Lock()
	r, ok := c.ipRecords[ip]
	if ok && r.ExpiresAt != nil && time.Now().After(*r.ExpiresAt) {
		delete(c.ipRecords, ip)
		c.mu.Unlock()
		if err := c.store.deleteIPRecord(ip); err != nil {
			log.WithError(err).Errorf("access control: failed to delete expired IP record %s", ip)
		}
		return
	}
	c.mu.Unlock()
}

// CheckModel returns the policy action for the given model.
func (c *Controller) CheckModel(model string) ModelCheckResult {
	c.mu.RLock()
	p, ok := c.modelPolicies[model]
	c.mu.RUnlock()
	if !ok {
		return ModelCheckResult{Action: ActionAllow}
	}
	return ModelCheckResult{
		Action:    p.Action,
		RouteTo:   p.RouteTo,
		ChannelTo: p.ChannelTo,
	}
}

// RecordInvalidModel records an invalid model request from the given IP
// and triggers auto-policy if threshold is exceeded.
func (c *Controller) RecordInvalidModel(ip string) {
	c.invalidModelWindow.record(ip, time.Now())
	c.mu.RLock()
	ap, ok := c.autoPolicies[PolicyInvalidModel]
	c.mu.RUnlock()
	if !ok || ap.Action == "none" || ap.Threshold <= 0 {
		return
	}
	cnt := c.invalidModelWindow.count(ip, time.Duration(ap.Window)*time.Second)
	if cnt >= ap.Threshold {
		c.applyAutoAction(ip, ap, "auto: excessive invalid model requests")
	}
}

// RecordInvalidAPIKey records an invalid API key request from the given IP
// and triggers auto-policy if threshold is exceeded.
func (c *Controller) RecordInvalidAPIKey(ip string) {
	c.invalidAPIKeyWindow.record(ip, time.Now())
	c.mu.RLock()
	ap, ok := c.autoPolicies[PolicyInvalidAPIKey]
	c.mu.RUnlock()
	if !ok || ap.Action == "none" || ap.Threshold <= 0 {
		return
	}
	cnt := c.invalidAPIKeyWindow.count(ip, time.Duration(ap.Window)*time.Second)
	if cnt >= ap.Threshold {
		c.applyAutoAction(ip, ap, "auto: excessive invalid API key requests")
	}
}

func (c *Controller) applyAutoAction(ip string, ap AutoPolicy, reason string) {
	switch ap.Action {
	case "ban":
		var expires *time.Time
		if ap.Duration > 0 {
			t := time.Now().Add(time.Duration(ap.Duration) * time.Second)
			expires = &t
		}
		c.setIPRecord(IPRecord{
			IP:        ip,
			Status:    StatusBanned,
			Reason:    reason,
			ExpiresAt: expires,
			CreatedAt: time.Now(),
		})
		log.Warnf("access control: auto-banned IP %s: %s", ip, reason)
	case "risk_control":
		dur := ap.Duration
		if dur <= 0 {
			dur = 3600
		}
		t := time.Now().Add(time.Duration(dur) * time.Second)
		c.setIPRecord(IPRecord{
			IP:        ip,
			Status:    StatusRiskControlled,
			Reason:    reason,
			ExpiresAt: &t,
			CreatedAt: time.Now(),
		})
		log.Warnf("access control: auto risk-controlled IP %s for %ds: %s", ip, dur, reason)
	}
}

// --- Management methods ---

func (c *Controller) SetModelPolicy(p ModelPolicy) error {
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Now()
	}
	c.mu.Lock()
	c.modelPolicies[p.Model] = p
	c.mu.Unlock()
	return c.store.upsertModelPolicy(p)
}

func (c *Controller) RemoveModelPolicy(model string) error {
	c.mu.Lock()
	delete(c.modelPolicies, model)
	c.mu.Unlock()
	return c.store.deleteModelPolicy(model)
}

func (c *Controller) ListModelPolicies() []ModelPolicy {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]ModelPolicy, 0, len(c.modelPolicies))
	for _, p := range c.modelPolicies {
		out = append(out, p)
	}
	return out
}

func (c *Controller) BanIP(ip, reason string) error {
	return c.setIPRecord(IPRecord{
		IP:        ip,
		Status:    StatusBanned,
		Reason:    reason,
		CreatedAt: time.Now(),
	})
}

func (c *Controller) RiskControlIP(ip string, durationSec int, reason string) error {
	t := time.Now().Add(time.Duration(durationSec) * time.Second)
	return c.setIPRecord(IPRecord{
		IP:        ip,
		Status:    StatusRiskControlled,
		Reason:    reason,
		ExpiresAt: &t,
		CreatedAt: time.Now(),
	})
}

func (c *Controller) UnbanIP(ip string) error {
	c.mu.Lock()
	delete(c.ipRecords, ip)
	c.mu.Unlock()
	return c.store.deleteIPRecord(ip)
}

func (c *Controller) setIPRecord(r IPRecord) error {
	c.mu.Lock()
	c.ipRecords[r.IP] = r
	c.mu.Unlock()
	return c.store.upsertIPRecord(r)
}

func (c *Controller) ListIPRecords() []IPRecord {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]IPRecord, 0, len(c.ipRecords))
	for _, r := range c.ipRecords {
		out = append(out, r)
	}
	return out
}

func (c *Controller) SetAutoPolicy(a AutoPolicy) error {
	c.mu.Lock()
	c.autoPolicies[a.Type] = a
	c.mu.Unlock()
	return c.store.upsertAutoPolicy(a)
}

func (c *Controller) GetAutoPolicies() []AutoPolicy {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]AutoPolicy, 0, len(c.autoPolicies))
	for _, a := range c.autoPolicies {
		out = append(out, a)
	}
	return out
}

// GetIPStats returns the current sliding window counts for the given IP.
func (c *Controller) GetIPStats(ip string) map[string]int {
	stats := make(map[string]int)
	c.mu.RLock()
	apModel := c.autoPolicies[PolicyInvalidModel]
	apKey := c.autoPolicies[PolicyInvalidAPIKey]
	c.mu.RUnlock()

	modelWindow := time.Duration(apModel.Window) * time.Second
	if modelWindow <= 0 {
		modelWindow = 5 * time.Minute
	}
	keyWindow := time.Duration(apKey.Window) * time.Second
	if keyWindow <= 0 {
		keyWindow = 5 * time.Minute
	}
	stats["invalid_model_count"] = c.invalidModelWindow.count(ip, modelWindow)
	stats["invalid_apikey_count"] = c.invalidAPIKeyWindow.count(ip, keyWindow)
	return stats
}

// GetAllIPStats returns sliding window counts for all tracked IPs.
func (c *Controller) GetAllIPStats() map[string]map[string]int {
	c.mu.RLock()
	apModel := c.autoPolicies[PolicyInvalidModel]
	apKey := c.autoPolicies[PolicyInvalidAPIKey]
	c.mu.RUnlock()

	modelWindow := time.Duration(apModel.Window) * time.Second
	if modelWindow <= 0 {
		modelWindow = 5 * time.Minute
	}
	keyWindow := time.Duration(apKey.Window) * time.Second
	if keyWindow <= 0 {
		keyWindow = 5 * time.Minute
	}

	result := make(map[string]map[string]int)

	c.invalidModelWindow.mu.Lock()
	for ip := range c.invalidModelWindow.buckets {
		if _, ok := result[ip]; !ok {
			result[ip] = make(map[string]int)
		}
	}
	c.invalidModelWindow.mu.Unlock()

	c.invalidAPIKeyWindow.mu.Lock()
	for ip := range c.invalidAPIKeyWindow.buckets {
		if _, ok := result[ip]; !ok {
			result[ip] = make(map[string]int)
		}
	}
	c.invalidAPIKeyWindow.mu.Unlock()

	for ip, m := range result {
		m["invalid_model_count"] = c.invalidModelWindow.count(ip, modelWindow)
		m["invalid_apikey_count"] = c.invalidAPIKeyWindow.count(ip, keyWindow)
	}
	return result
}

func (c *Controller) cleanupLoop() {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.purgeExpiredIPs()
			c.invalidModelWindow.purgeOlderThan(30 * time.Minute)
			c.invalidAPIKeyWindow.purgeOlderThan(30 * time.Minute)
		}
	}
}

func (c *Controller) purgeExpiredIPs() {
	now := time.Now()
	c.mu.Lock()
	var toDelete []string
	for ip, r := range c.ipRecords {
		if r.ExpiresAt != nil && now.After(*r.ExpiresAt) {
			toDelete = append(toDelete, ip)
			delete(c.ipRecords, ip)
		}
	}
	c.mu.Unlock()
	for _, ip := range toDelete {
		if err := c.store.deleteIPRecord(ip); err != nil {
			log.WithError(err).Errorf("access control: cleanup failed for IP %s", ip)
		}
	}
}
