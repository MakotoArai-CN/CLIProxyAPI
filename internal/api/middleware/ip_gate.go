package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/accesscontrol"
)

func IPGateMiddleware(ctrl *accesscontrol.Controller) gin.HandlerFunc {
	return func(c *gin.Context) {
		if ctrl == nil {
			c.Next()
			return
		}
		ip := c.ClientIP()
		c.Set("clientIP", ip)

		result := ctrl.CheckIP(ip)
		if !result.Blocked {
			c.Next()
			return
		}

		switch result.Status {
		case accesscontrol.StatusBanned:
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": gin.H{
					"message": "IP banned: " + result.Reason,
					"type":    "access_denied",
				},
			})
		case accesscontrol.StatusRiskControlled:
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": gin.H{
					"message": "IP temporarily restricted: " + result.Reason,
					"type":    "rate_limited",
				},
			})
		default:
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": gin.H{
					"message": "access denied",
					"type":    "access_denied",
				},
			})
		}
	}
}
