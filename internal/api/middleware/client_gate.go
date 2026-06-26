package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/accesscontrol"
)

// ClientGateMiddleware enforces the client whitelist when it is active.
// It reads User-Agent and X-Proxy-Client headers to identify the caller,
// stores the detected client_id in the gin context, and rejects unknown
// clients with 403 when the whitelist is enabled.
func ClientGateMiddleware(ctrl *accesscontrol.Controller) gin.HandlerFunc {
	return func(c *gin.Context) {
		if ctrl == nil {
			c.Next()
			return
		}
		ua := c.GetHeader("User-Agent")
		xpc := c.GetHeader("X-Proxy-Client")

		allowed, clientID, _ := ctrl.CheckClient(ua, xpc)
		c.Set("clientID", clientID)

		if !allowed {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": gin.H{
					"message": "client not allowed: " + clientID,
					"type":    "client_not_allowed",
				},
			})
			return
		}
		c.Next()
	}
}
