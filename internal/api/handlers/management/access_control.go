package management

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/accesscontrol"
)

// GetModelPolicies returns all configured model policies.
func (h *Handler) GetModelPolicies(c *gin.Context) {
	if h.accessCtrl == nil {
		c.JSON(http.StatusOK, gin.H{"model_policies": []any{}})
		return
	}
	c.JSON(http.StatusOK, gin.H{"model_policies": h.accessCtrl.ListModelPolicies()})
}

// PutModelPolicy creates or updates a model policy.
func (h *Handler) PutModelPolicy(c *gin.Context) {
	if h.accessCtrl == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "access control not enabled"})
		return
	}
	var body accesscontrol.ModelPolicy
	if err := c.ShouldBindJSON(&body); err != nil || body.Model == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body: model and action are required"})
		return
	}
	if body.Action == "" {
		body.Action = accesscontrol.ActionDeny
	}
	if err := h.accessCtrl.SetModelPolicy(body); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save model policy: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// DeleteModelPolicy removes a model policy.
func (h *Handler) DeleteModelPolicy(c *gin.Context) {
	if h.accessCtrl == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "access control not enabled"})
		return
	}
	model := c.Query("model")
	if model == "" {
		var body struct {
			Model string `json:"model"`
		}
		if err := c.ShouldBindJSON(&body); err == nil {
			model = body.Model
		}
	}
	if model == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "model parameter required"})
		return
	}
	if err := h.accessCtrl.RemoveModelPolicy(model); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete model policy: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// GetIPRecords returns all IP ban/risk-control records.
func (h *Handler) GetIPRecords(c *gin.Context) {
	if h.accessCtrl == nil {
		c.JSON(http.StatusOK, gin.H{"ip_records": []any{}})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ip_records": h.accessCtrl.ListIPRecords()})
}

// PutIPRecord bans or risk-controls an IP.
func (h *Handler) PutIPRecord(c *gin.Context) {
	if h.accessCtrl == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "access control not enabled"})
		return
	}
	var body struct {
		IP       string `json:"ip"`
		Action   string `json:"action"`
		Reason   string `json:"reason"`
		Duration int    `json:"duration_seconds"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.IP == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body: ip and action are required"})
		return
	}
	var err error
	switch body.Action {
	case "ban":
		err = h.accessCtrl.BanIP(body.IP, body.Reason)
	case "risk_control":
		dur := body.Duration
		if dur <= 0 {
			dur = 3600
		}
		err = h.accessCtrl.RiskControlIP(body.IP, dur, body.Reason)
	case "unban", "remove":
		err = h.accessCtrl.UnbanIP(body.IP)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "action must be ban, risk_control, or unban"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update IP record: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// DeleteIPRecord removes an IP record (unban).
func (h *Handler) DeleteIPRecord(c *gin.Context) {
	if h.accessCtrl == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "access control not enabled"})
		return
	}
	ip := c.Query("ip")
	if ip == "" {
		var body struct {
			IP string `json:"ip"`
		}
		if err := c.ShouldBindJSON(&body); err == nil {
			ip = body.IP
		}
	}
	if ip == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ip parameter required"})
		return
	}
	if err := h.accessCtrl.UnbanIP(ip); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete IP record: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// GetAutoPolicies returns the auto-policy configuration.
func (h *Handler) GetAutoPolicies(c *gin.Context) {
	if h.accessCtrl == nil {
		c.JSON(http.StatusOK, gin.H{"auto_policies": []any{}})
		return
	}
	c.JSON(http.StatusOK, gin.H{"auto_policies": h.accessCtrl.GetAutoPolicies()})
}

// PutAutoPolicy creates or updates an auto-policy.
func (h *Handler) PutAutoPolicy(c *gin.Context) {
	if h.accessCtrl == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "access control not enabled"})
		return
	}
	var body accesscontrol.AutoPolicy
	if err := c.ShouldBindJSON(&body); err != nil || body.Type == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body: type is required"})
		return
	}
	if body.Type != accesscontrol.PolicyInvalidModel && body.Type != accesscontrol.PolicyInvalidAPIKey {
		c.JSON(http.StatusBadRequest, gin.H{"error": "type must be invalid_model or invalid_apikey"})
		return
	}
	if err := h.accessCtrl.SetAutoPolicy(body); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save auto-policy: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// GetAccessControlStats returns per-IP sliding window counters.
func (h *Handler) GetAccessControlStats(c *gin.Context) {
	if h.accessCtrl == nil {
		c.JSON(http.StatusOK, gin.H{"stats": map[string]any{}})
		return
	}
	ip := c.Query("ip")
	if ip != "" {
		c.JSON(http.StatusOK, gin.H{"ip": ip, "stats": h.accessCtrl.GetIPStats(ip)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"stats": h.accessCtrl.GetAllIPStats()})
}

// GetClientWhitelist returns the client whitelist state.
func (h *Handler) GetClientWhitelist(c *gin.Context) {
	if h.accessCtrl == nil {
		c.JSON(http.StatusOK, gin.H{"active": false, "entries": []any{}, "presets": accesscontrol.ClientPresets()})
		return
	}
	state := h.accessCtrl.GetClientWhitelistState()
	c.JSON(http.StatusOK, gin.H{
		"active":  state.Active,
		"entries": state.Entries,
	})
}

// PutClientWhitelistActive toggles the client whitelist on/off.
func (h *Handler) PutClientWhitelistActive(c *gin.Context) {
	if h.accessCtrl == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "access control not enabled"})
		return
	}
	var body struct {
		Active bool `json:"active"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	if err := h.accessCtrl.SetClientWhitelistActive(body.Active); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// UpsertClientEntry creates or updates a client whitelist entry.
func (h *Handler) UpsertClientEntry(c *gin.Context) {
	if h.accessCtrl == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "access control not enabled"})
		return
	}
	var body accesscontrol.ClientEntry
	if err := c.ShouldBindJSON(&body); err != nil || body.ClientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body: client_id is required"})
		return
	}
	if err := h.accessCtrl.UpsertClientEntry(body); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// DeleteClientEntry removes a client whitelist entry.
func (h *Handler) DeleteClientEntry(c *gin.Context) {
	if h.accessCtrl == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "access control not enabled"})
		return
	}
	clientID := c.Query("client_id")
	if clientID == "" {
		var body struct {
			ClientID string `json:"client_id"`
		}
		if err := c.ShouldBindJSON(&body); err == nil {
			clientID = body.ClientID
		}
	}
	if clientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "client_id parameter required"})
		return
	}
	if err := h.accessCtrl.RemoveClientEntry(clientID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// GetClientPresets returns the built-in known client list.
func (h *Handler) GetClientPresets(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"presets": accesscontrol.ClientPresets()})
}
