package middleware

import (
	"bytes"
	"fmt"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
)

// LimitRequestBody refuses a request whose body is larger than limit bytes,
// with 413, before any handler reads it.
//
// Handlers decode JSON with ShouldBindJSON, which reads the whole body to do
// it. Unbounded, a sign-in — which anybody can send — could be made to hold as
// much memory as the sender cared to transmit. A declared Content-Length over
// the limit is refused without reading anything; an undeclared (chunked) body
// is read no further than one byte past the limit. What fits is handed on
// unchanged, so the agent middleware's signature check and the ACME server's
// own tighter limit see exactly the bytes that were sent.
func LimitRequestBody(limit int64) gin.HandlerFunc {
	tooLarge := func(c *gin.Context) {
		c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, gin.H{
			"error": fmt.Sprintf("request body is larger than the %d bytes the API accepts", limit),
		})
	}
	return func(c *gin.Context) {
		if c.Request.Body == nil || c.Request.Body == http.NoBody {
			c.Next()
			return
		}
		if c.Request.ContentLength > limit {
			tooLarge(c)
			return
		}
		body, err := io.ReadAll(io.LimitReader(c.Request.Body, limit+1))
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "could not read the request body: " + err.Error()})
			return
		}
		if int64(len(body)) > limit {
			tooLarge(c)
			return
		}
		c.Request.Body = io.NopCloser(bytes.NewReader(body))
		c.Next()
	}
}
