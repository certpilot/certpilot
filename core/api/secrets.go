package api

import (
	"log/slog"
	"net/http"

	"github.com/certpilot/certpilot/core/engine/rekey"
	"github.com/certpilot/certpilot/core/store"
	"github.com/certpilot/certpilot/pkg/secrets"
	"github.com/gin-gonic/gin"
)

// SecretsHandler answers questions about the key encryption keys, as opposed
// to anything they seal.
type SecretsHandler struct {
	store   store.Store
	keyring *secrets.Keyring
}

// NewSecretsHandler creates a new SecretsHandler.
func NewSecretsHandler(s store.Store, kr *secrets.Keyring) *SecretsHandler {
	return &SecretsHandler{store: s, keyring: kr}
}

// Keys handles GET /api/v1/secrets/keys.
//
// For each key the database names or this core holds: how many sealed records
// depend on it, by kind, and which audit entries it signed. It is what to read
// before dropping a retired key, and after `certpilot-core --reseal` to see
// that nothing is left on one. Nothing is opened to produce it, so it also
// names keys this core was never given.
func (h *SecretsHandler) Keys(c *gin.Context) {
	report, err := rekey.Survey(c.Request.Context(), h.store, h.keyring)
	if err != nil {
		slog.Error("the key report could not be produced", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "the key report could not be produced"})
		return
	}
	c.JSON(http.StatusOK, report)
}
