package api

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/certpilot/certpilot/core/store"
	"github.com/gin-gonic/gin"
)

// respondLookup answers a store lookup that returned an error.
//
// A record that does not exist is 404, with the store's own message
// ("certificate … not found"). Anything else is a failure to read it, which is
// the server's problem rather than the caller's: 500, with the cause logged and
// kept out of the response. Every lookup used to answer 404 for both, so a
// database outage, or a column missing after a skipped migration, told the
// client that the record had been deleted, and handed it the database's own
// error text (#135).
func respondLookup(c *gin.Context, err error, what string) {
	if errors.Is(err, store.ErrNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	slog.Error("could not read "+what, "path", c.FullPath(), "error", err)
	c.JSON(http.StatusInternalServerError, gin.H{"error": "could not read the " + what})
}
