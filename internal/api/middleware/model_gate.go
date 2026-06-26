package middleware

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/accesscontrol"
)

func ModelGateMiddleware(ctrl *accesscontrol.Controller) gin.HandlerFunc {
	return func(c *gin.Context) {
		if ctrl == nil {
			c.Next()
			return
		}

		if c.Request.Body == nil || c.Request.ContentLength == 0 {
			c.Next()
			return
		}

		bodyBytes, err := io.ReadAll(c.Request.Body)
		if err != nil {
			c.Next()
			return
		}
		c.Request.Body = io.NopCloser(bytes.NewReader(bodyBytes))

		var partial struct {
			Model string `json:"model"`
		}
		if err = json.Unmarshal(bodyBytes, &partial); err != nil || partial.Model == "" {
			c.Next()
			return
		}

		clientIP, _ := c.Get("clientIP")
		ip, _ := clientIP.(string)
		if ip == "" {
			ip = c.ClientIP()
		}

		result := ctrl.CheckModelWithIP(partial.Model, ip)

		switch result.Action {
		case accesscontrol.ActionAllow, "":
			c.Next()
		case accesscontrol.ActionDeny:
			ctrl.RecordInvalidModel(ip)
			msg := "model " + partial.Model + " is not available"
			if result.Reason != "" {
				msg = result.Reason
			}
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{
				"error": gin.H{
					"message": msg,
					"type":    "model_unavailable",
				},
			})
		case accesscontrol.ActionRoute:
			rewritten := bytes.Replace(bodyBytes, []byte(`"`+partial.Model+`"`), []byte(`"`+result.RouteTo+`"`), 1)
			c.Request.Body = io.NopCloser(bytes.NewReader(rewritten))
			c.Request.ContentLength = int64(len(rewritten))
			c.Next()
		case accesscontrol.ActionChannel:
			c.Set("forceChannel", result.ChannelTo)
			c.Next()
		default:
			c.Next()
		}
	}
}
