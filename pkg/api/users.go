package api

import (
	"net/http"
	"time"

	"github.com/deb-ict/go-identity/pkg/account"
	"github.com/deb-ict/go-identity/pkg/identity"
	"github.com/deb-ict/go-identity/pkg/router"
	"github.com/deb-ict/go-identity/pkg/store"
)

// User is the API representation of a user. The password hash is never exposed.
type User struct {
	Id               string     `json:"id"`
	Username         string     `json:"username"`
	Email            string     `json:"email"`
	EmailVerified    bool       `json:"email_verified"`
	Enabled          bool       `json:"enabled"`
	HasPassword      bool       `json:"has_password"`
	LockedOut        bool       `json:"locked_out"`
	LockoutEnd       *time.Time `json:"lockout_end,omitempty"`
	FailedLoginCount int        `json:"failed_login_count"`
	LastLoginAt      *time.Time `json:"last_login_at,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

// CreateUserRequest creates a user.
type CreateUserRequest struct {
	Username      string `json:"username"`
	Email         string `json:"email"`
	Password      string `json:"password"`
	EmailVerified bool   `json:"email_verified"`
	Enabled       *bool  `json:"enabled"`
	// SendActivation sends the activation email when the email is not verified.
	SendActivation bool `json:"send_activation"`
}

// UpdateUserRequest updates the profile and status of a user.
type UpdateUserRequest struct {
	Username      string `json:"username"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Enabled       bool   `json:"enabled"`
}

// PasswordRequest sets the password of a user.
type PasswordRequest struct {
	Password string `json:"password"`
}

// RevokeResponse reports the number of revoked tokens.
type RevokeResponse struct {
	AccessTokens  int `json:"access_tokens"`
	RefreshTokens int `json:"refresh_tokens"`
}

func (a *API) toUser(u *identity.User) *User {
	return &User{
		Id:               u.Id,
		Username:         u.Username,
		Email:            u.Email,
		EmailVerified:    u.EmailVerified,
		Enabled:          u.Enabled,
		HasPassword:      u.PasswordHash != "",
		LockedOut:        u.IsLockedOut(a.now()),
		LockoutEnd:       u.LockoutEnd,
		FailedLoginCount: u.FailedLoginCount,
		LastLoginAt:      u.LastLoginAt,
		CreatedAt:        u.CreatedAt,
		UpdatedAt:        u.UpdatedAt,
	}
}

func (a *API) listUsers(w http.ResponseWriter, r *http.Request) {
	opts, ok := listOptions(w, r)
	if !ok {
		return
	}
	users, total, err := a.opts.Store.ListUsers(r.Context(), store.UserFilter{Search: r.URL.Query().Get("search")}, opts)
	if err != nil {
		a.handleError(w, r, err)
		return
	}
	respondList(w, users, total, opts, a.toUser)
}

func (a *API) getUser(w http.ResponseWriter, r *http.Request) {
	user, err := a.opts.Accounts.GetUser(r.Context(), router.Param(r, "id"))
	if err != nil {
		a.handleError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, a.toUser(user))
}

func (a *API) createUser(w http.ResponseWriter, r *http.Request) {
	req := &CreateUserRequest{}
	if !decode(w, r, req) {
		return
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	user, err := a.opts.Accounts.CreateUser(r.Context(), account.CreateUserInput{
		Username:       req.Username,
		Email:          req.Email,
		Password:       req.Password,
		EmailVerified:  req.EmailVerified,
		Enabled:        enabled,
		SendActivation: req.SendActivation,
	})
	if err != nil {
		a.handleError(w, r, err)
		return
	}
	w.Header().Set("Location", r.URL.Path+"/"+user.Id)
	writeJSON(w, http.StatusCreated, a.toUser(user))
}

func (a *API) updateUser(w http.ResponseWriter, r *http.Request) {
	req := &UpdateUserRequest{}
	if !decode(w, r, req) {
		return
	}
	user, err := a.opts.Accounts.GetUser(r.Context(), router.Param(r, "id"))
	if err != nil {
		a.handleError(w, r, err)
		return
	}
	user.Username = req.Username
	user.Email = req.Email
	user.EmailVerified = req.EmailVerified
	user.Enabled = req.Enabled
	if err := a.opts.Accounts.UpdateUser(r.Context(), user); err != nil {
		a.handleError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, a.toUser(user))
}

func (a *API) deleteUser(w http.ResponseWriter, r *http.Request) {
	if err := a.opts.Accounts.DeleteUser(r.Context(), router.Param(r, "id")); err != nil {
		a.handleError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) setUserPassword(w http.ResponseWriter, r *http.Request) {
	req := &PasswordRequest{}
	if !decode(w, r, req) {
		return
	}
	if err := a.opts.Accounts.SetPassword(r.Context(), router.Param(r, "id"), req.Password); err != nil {
		a.handleError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) unlockUser(w http.ResponseWriter, r *http.Request) {
	user, err := a.opts.Accounts.GetUser(r.Context(), router.Param(r, "id"))
	if err != nil {
		a.handleError(w, r, err)
		return
	}
	user.LockoutEnd = nil
	user.FailedLoginCount = 0
	if err := a.opts.Accounts.UpdateUser(r.Context(), user); err != nil {
		a.handleError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, a.toUser(user))
}

func (a *API) sendUserActivation(w http.ResponseWriter, r *http.Request) {
	user, err := a.opts.Accounts.GetUser(r.Context(), router.Param(r, "id"))
	if err != nil {
		a.handleError(w, r, err)
		return
	}
	if user.EmailVerified {
		writeError(w, http.StatusConflict, "conflict", "the email address is already verified")
		return
	}
	if err := a.opts.Accounts.SendActivation(r.Context(), user); err != nil {
		a.handleError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func (a *API) sendUserPasswordReset(w http.ResponseWriter, r *http.Request) {
	user, err := a.opts.Accounts.GetUser(r.Context(), router.Param(r, "id"))
	if err != nil {
		a.handleError(w, r, err)
		return
	}
	if !user.Enabled {
		writeError(w, http.StatusConflict, "conflict", "the user is disabled")
		return
	}
	if err := a.opts.Accounts.RequestPasswordReset(r.Context(), user.Email); err != nil {
		a.handleError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func (a *API) revokeUserTokens(w http.ResponseWriter, r *http.Request) {
	user, err := a.opts.Accounts.GetUser(r.Context(), router.Param(r, "id"))
	if err != nil {
		a.handleError(w, r, err)
		return
	}
	filter := store.TokenFilter{UserId: user.Id}
	refreshTokens, err := a.opts.Store.DeleteRefreshTokens(r.Context(), filter)
	if err != nil {
		a.handleError(w, r, err)
		return
	}
	accessTokens, err := a.opts.Store.DeleteAccessTokens(r.Context(), filter)
	if err != nil {
		a.handleError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, &RevokeResponse{AccessTokens: accessTokens, RefreshTokens: refreshTokens})
}
