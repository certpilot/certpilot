package api

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/certpilot/certpilot/core/server/middleware"
	"github.com/certpilot/certpilot/core/store"
	"github.com/certpilot/certpilot/pkg/passwords"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// UserHandler manages accounts.
//
// Every route here is admin. Reading the list is included, and that is
// deliberate rather than cautious: the list is a map of who can do what to the
// CA hierarchy, and it is exactly what somebody who has taken over one account
// wants next.
type UserHandler struct {
	store store.Store
}

func NewUserHandler(s store.Store) *UserHandler {
	return &UserHandler{store: s}
}

// List handles GET /api/v1/users.
func (h *UserHandler) List(c *gin.Context) {
	users, err := h.store.ListUsers(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": users, "total": len(users)})
}

// CreateUserInput describes a new local account.
type CreateUserInput struct {
	Email       string `json:"email" binding:"required,email"`
	DisplayName string `json:"display_name"`
	Role        string `json:"role" binding:"required"`
	// Password is optional. Omitted, CertPilot generates one and returns it
	// once — which is the better default, because a password chosen by the
	// person creating the account is a password two people know.
	Password string `json:"password"`
}

// Create handles POST /api/v1/users.
func (h *UserHandler) Create(c *gin.Context) {
	var input CreateUserInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "an email address and a role are required"})
		return
	}
	if !store.ValidRole(input.Role) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("%q is not a role: viewer, auditor, operator, admin", input.Role),
		})
		return
	}

	email := strings.TrimSpace(input.Email)
	existing, err := h.store.UserByEmail(c.Request.Context(), email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if existing != nil {
		c.JSON(http.StatusConflict, gin.H{
			"error": "an account already exists for that address. Change its role rather than " +
				"creating a second one — two rows for one person makes the audit log ambiguous",
		})
		return
	}

	password := input.Password
	generated := password == ""
	if generated {
		password, err = generateInitialPassword()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "could not generate a password"})
			return
		}
	} else if err := passwords.Validate(password); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Created through ResolveUser so that a local account is shaped exactly
	// like a federated one: same table, same columns, same subject semantics.
	// Nothing downstream should be able to tell them apart.
	user, err := h.store.ResolveUser(c.Request.Context(), store.UserIdentity{
		Issuer:      store.LocalIssuer,
		Subject:     uuid.NewString(),
		Email:       email,
		DisplayName: strings.TrimSpace(input.DisplayName),
	}, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// must_change is set whether or not the password was generated. Either way
	// somebody other than the account holder currently knows it.
	if err := h.store.SetUserPassword(c.Request.Context(), user.ID, password, true); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if user.Role != input.Role {
		if updated, err := h.store.SetUserRole(c.Request.Context(), user.ID, input.Role); err == nil && updated != nil {
			user = updated
		}
	}

	h.audit(c, "user.created", user, map[string]any{
		"role": input.Role, "password_generated": generated,
	})

	response := gin.H{"user": user}
	if generated {
		// Returned once, in the response body only. Never logged: an initial
		// password in an API log is a credential in a log aggregator.
		response["initial_password"] = password
		response["message"] = "Account created. This password is shown once and cannot be recovered."
	}
	c.JSON(http.StatusCreated, response)
}

// UpdateUserInput carries only what an administrator may change. Pointers, so
// that omitting a field leaves it alone rather than blanking it.
type UpdateUserInput struct {
	Role   *string `json:"role"`
	Status *string `json:"status"`
}

// Update handles PATCH /api/v1/users/:id.
func (h *UserHandler) Update(c *gin.Context) {
	id := c.Param("id")

	var input UpdateUserInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "nothing to change"})
		return
	}

	user, err := h.store.GetUser(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if user == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "no such account"})
		return
	}

	// The guard that makes this screen safe to use. Demoting or suspending the
	// last administrator locks everybody out of the CA hierarchy, and the only
	// way back is SQL — which is precisely the situation this screen exists to
	// remove.
	if wouldRemoveLastAdmin(user, input) {
		remaining, err := h.countOtherActiveAdmins(c, user.ID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if remaining == 0 {
			c.JSON(http.StatusConflict, gin.H{
				"error": "this is the only active administrator. Promote somebody else first — " +
					"otherwise nobody can administer CertPilot and the only way back is a SQL update",
			})
			return
		}
	}

	if input.Role != nil {
		if !store.ValidRole(*input.Role) {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": fmt.Sprintf("%q is not a role: viewer, auditor, operator, admin", *input.Role),
			})
			return
		}
		updated, err := h.store.SetUserRole(c.Request.Context(), id, *input.Role)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		user = updated
		h.audit(c, "user.role_changed", user, map[string]any{"role": *input.Role})
	}

	if input.Status != nil {
		if *input.Status != store.UserStatusActive && *input.Status != store.UserStatusSuspended {
			c.JSON(http.StatusBadRequest, gin.H{"error": "status must be ACTIVE or SUSPENDED"})
			return
		}
		updated, err := h.store.SetUserStatus(c.Request.Context(), id, *input.Status)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		user = updated

		// Suspending has to end sessions, or it means nothing until the
		// person's current one expires — which on a console left open is
		// however long they leave it open.
		if *input.Status == store.UserStatusSuspended {
			ended, err := h.store.RevokeSessionsForUser(c.Request.Context(), id)
			if err != nil {
				slog.Error("suspended an account but could not end its sessions",
					"error", err, "user_id", id)
			}
			h.audit(c, "user.suspended", user, map[string]any{"sessions_ended": ended})
		} else {
			h.audit(c, "user.reinstated", user, nil)
		}
	}

	c.JSON(http.StatusOK, gin.H{"user": user})
}

// ResetPassword handles POST /api/v1/users/:id/password.
//
// An administrator setting somebody else's password does not need to know the
// old one, which is the whole point — this is the path back from a locked-out
// colleague. It ends every session that account holds, because the usual reason
// to reset a password is believing somebody else has it.
func (h *UserHandler) ResetPassword(c *gin.Context) {
	id := c.Param("id")

	user, err := h.store.GetUser(c.Request.Context(), id)
	if err != nil {
		respondLookup(c, err, "account")
		return
	}
	if user == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "no such account"})
		return
	}

	password, err := generateInitialPassword()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not generate a password"})
		return
	}
	if err := h.store.SetUserPassword(c.Request.Context(), id, password, true); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	ended, err := h.store.RevokeSessionsForUser(c.Request.Context(), id)
	if err != nil {
		slog.Warn("reset a password but could not end existing sessions", "error", err, "user_id", id)
	}

	h.audit(c, "user.password_reset", user, map[string]any{"sessions_ended": ended})

	c.JSON(http.StatusOK, gin.H{
		"initial_password": password,
		"message": "This password is shown once and cannot be recovered. " +
			"Every session that account held has been ended.",
	})
}

func wouldRemoveLastAdmin(user *store.User, input UpdateUserInput) bool {
	if user.Role != store.RoleAdmin || !user.IsActive() {
		return false
	}
	if input.Role != nil && *input.Role != store.RoleAdmin {
		return true
	}
	return input.Status != nil && *input.Status == store.UserStatusSuspended
}

func (h *UserHandler) countOtherActiveAdmins(c *gin.Context, excluding string) (int, error) {
	users, err := h.store.ListUsers(c.Request.Context())
	if err != nil {
		return 0, err
	}
	n := 0
	for _, u := range users {
		if u.ID != excluding && u.Role == store.RoleAdmin && u.IsActive() {
			n++
		}
	}
	return n, nil
}

// generateInitialPassword produces a readable random password.
//
// The alphabet omits characters misread when copied off a screen — 0/O and
// 1/l/I — because this value is shown once and typed by hand, and one nobody
// can transcribe gets replaced with a weak one.
func generateInitialPassword() (string, error) {
	const alphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	const groups, groupLen = 4, 5

	var out strings.Builder
	for g := range groups {
		if g > 0 {
			out.WriteByte('-')
		}
		for range groupLen {
			n, err := randomIndex(len(alphabet))
			if err != nil {
				return "", err
			}
			out.WriteByte(alphabet[n])
		}
	}
	return out.String(), nil
}

func (h *UserHandler) audit(c *gin.Context, action string, user *store.User, details map[string]any) {
	actorID := c.GetString(middleware.ContextUserID)
	actorEmail := c.GetString(middleware.ContextUserEmail)
	ip := c.ClientIP()

	encoded := fmt.Sprintf(`{"subject": %q, "email": %q`, user.Subject, user.Email)
	for k, v := range details {
		encoded += fmt.Sprintf(`, %q: %v`, k, jsonScalar(v))
	}
	encoded += "}"

	entry := &store.AuditLog{
		Action:     action,
		EntityType: "user",
		EntityID:   &user.ID,
		ActorID:    &actorID,
		IPAddress:  &ip,
		Details:    encoded,
	}
	if actorEmail != "" {
		entry.ActorEmail = &actorEmail
	}
	_ = h.store.CreateAuditLog(c.Request.Context(), entry)
}

// jsonScalar renders a detail value safely. Only the shapes this file passes.
func jsonScalar(v any) string {
	switch typed := v.(type) {
	case string:
		return fmt.Sprintf("%q", typed)
	case bool:
		return fmt.Sprintf("%t", typed)
	default:
		return fmt.Sprintf("%v", typed)
	}
}
