// Package ui implements the HTML user interface of the identity server: login, logout,
// registration, account activation, password reset and the OAuth consent page.
//
// The UI implements oauth.Interaction, which connects it to the authorization endpoint.
package ui

import (
	"bytes"
	"embed"
	"errors"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/deb-ict/go-identity/pkg/account"
	"github.com/deb-ict/go-identity/pkg/identity"
	"github.com/deb-ict/go-identity/pkg/oauth"
	"github.com/deb-ict/go-identity/pkg/router"
	"github.com/deb-ict/go-identity/pkg/session"
)

//go:embed templates/*.html
var defaultTemplates embed.FS

// Paths of the UI pages, relative to the base path.
const (
	PathHome             = "/"
	PathLogin            = "/login"
	PathLogout           = "/logout"
	PathRegister         = "/register"
	PathActivate         = "/activate"
	PathActivationResend = "/activation/resend"
	PathPasswordForgot   = "/password/forgot"
	PathPasswordReset    = "/password/reset"
)

var pageNames = []string{"login", "register", "email_form", "password_reset", "consent", "message", "home", "logout"}

// Options configures the UI.
type Options struct {
	Accounts *account.Service
	Sessions *session.Manager
	// BasePath is the path prefix of the pages, e.g. "/identity".
	BasePath        string
	ApplicationName string
	// AllowRegistration enables self registration.
	AllowRegistration bool
	// Templates overrides the embedded templates. Missing files fall back to the embedded ones.
	// See pkg/ui/templates for the file names and the data they receive.
	Templates fs.FS
	Logger    *slog.Logger
}

// UI serves the HTML pages.
type UI struct {
	opts  Options
	pages map[string]*template.Template
}

var _ oauth.Interaction = &UI{}

// New creates the UI.
func New(opts Options) (*UI, error) {
	if opts.Accounts == nil || opts.Sessions == nil {
		return nil, errors.New("ui: accounts and sessions are required")
	}
	opts.BasePath = strings.TrimSuffix(opts.BasePath, "/")
	if opts.ApplicationName == "" {
		opts.ApplicationName = "Identity"
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	u := &UI{opts: opts, pages: map[string]*template.Template{}}
	funcs := template.FuncMap{"url": u.url}
	layout, err := u.readTemplate("layout.html")
	if err != nil {
		return nil, err
	}
	for _, name := range pageNames {
		content, err := u.readTemplate(name + ".html")
		if err != nil {
			return nil, err
		}
		t, err := template.New(name).Funcs(funcs).Parse(layout)
		if err == nil {
			_, err = t.Parse(content)
		}
		if err != nil {
			return nil, err
		}
		u.pages[name] = t
	}
	return u, nil
}

func (u *UI) readTemplate(name string) (string, error) {
	if u.opts.Templates != nil {
		data, err := fs.ReadFile(u.opts.Templates, name)
		if err == nil {
			return string(data), nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return "", err
		}
	}
	data, err := defaultTemplates.ReadFile("templates/" + name)
	return string(data), err
}

// url returns the absolute path of a page.
func (u *UI) url(path string) string {
	return u.opts.BasePath + path
}

// RegisterRoutes registers the pages. The router must already apply the base path.
func (u *UI) RegisterRoutes(r router.Router) {
	r.Handle(http.MethodGet, PathHome, http.HandlerFunc(u.home))
	r.Handle(http.MethodGet, PathLogin, http.HandlerFunc(u.loginPage))
	r.Handle(http.MethodPost, PathLogin, http.HandlerFunc(u.loginSubmit))
	r.Handle(http.MethodGet, PathLogout, http.HandlerFunc(u.logoutPage))
	r.Handle(http.MethodPost, PathLogout, http.HandlerFunc(u.logoutSubmit))
	if u.opts.AllowRegistration {
		r.Handle(http.MethodGet, PathRegister, http.HandlerFunc(u.registerPage))
		r.Handle(http.MethodPost, PathRegister, http.HandlerFunc(u.registerSubmit))
	}
	r.Handle(http.MethodGet, PathActivate, http.HandlerFunc(u.activate))
	r.Handle(http.MethodGet, PathActivationResend, http.HandlerFunc(u.resendPage))
	r.Handle(http.MethodPost, PathActivationResend, http.HandlerFunc(u.resendSubmit))
	r.Handle(http.MethodGet, PathPasswordForgot, http.HandlerFunc(u.forgotPage))
	r.Handle(http.MethodPost, PathPasswordForgot, http.HandlerFunc(u.forgotSubmit))
	r.Handle(http.MethodGet, PathPasswordReset, http.HandlerFunc(u.resetPage))
	r.Handle(http.MethodPost, PathPasswordReset, http.HandlerFunc(u.resetSubmit))
}

// Page is the data passed to the templates.
type Page struct {
	AppName string
	Title   string
	CSRF    string
	Error   string
	Info    string
	Success string
	User    *identity.User
	Form    map[string]string
	Data    any
}

// Link is a link shown on the message page.
type Link struct {
	Href string
	Text string
}

// MessageData is the data of the message page.
type MessageData struct {
	Message string
	Links   []Link
}

func (u *UI) render(w http.ResponseWriter, r *http.Request, status int, name string, page *Page) {
	page.AppName = u.opts.ApplicationName
	page.CSRF = u.opts.Sessions.CSRFToken(w, r)
	if page.Form == nil {
		page.Form = map[string]string{}
	}
	var buf bytes.Buffer
	if err := u.pages[name].ExecuteTemplate(&buf, "layout", page); err != nil {
		u.opts.Logger.ErrorContext(r.Context(), "failed to render page", "page", name, "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'")
	w.WriteHeader(status)
	w.Write(buf.Bytes())
}

func (u *UI) message(w http.ResponseWriter, r *http.Request, status int, title string, message string, links ...Link) {
	u.render(w, r, status, "message", &Page{Title: title, Data: &MessageData{Message: message, Links: links}})
}

func (u *UI) serverError(w http.ResponseWriter, r *http.Request, err error) {
	u.opts.Logger.ErrorContext(r.Context(), "request failed", "path", r.URL.Path, "error", err)
	u.message(w, r, http.StatusInternalServerError, "Something went wrong", "An unexpected error occurred. Please try again later.")
}

func (u *UI) redirect(w http.ResponseWriter, r *http.Request, target string) {
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, target, http.StatusSeeOther)
}

// safeReturnTo only accepts local paths, to prevent open redirects.
func (u *UI) safeReturnTo(returnTo string) string {
	// A local path starts with a single '/': "//host" and "/\\host" are protocol relative URLs in browsers
	if len(returnTo) == 0 || returnTo[0] != '/' || len(returnTo) > 1 && (returnTo[1] == '/' || returnTo[1] == '\\') ||
		strings.ContainsAny(returnTo, "\\\r\n\t") {
		return u.url(PathHome)
	}
	parsed, err := url.Parse(returnTo)
	if err != nil || parsed.Scheme != "" || parsed.Host != "" {
		return u.url(PathHome)
	}
	return returnTo
}

func (u *UI) verifyCSRF(w http.ResponseWriter, r *http.Request) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		return false
	}
	return u.opts.Sessions.VerifyCSRF(r)
}

const csrfMessage = "Your form has expired. Please try again."

// CurrentUser returns the user of a valid session. Sessions of users that changed their
// credentials or can't sign in anymore are removed.
func (u *UI) CurrentUser(w http.ResponseWriter, r *http.Request) (*identity.User, error) {
	s, ok := u.opts.Sessions.Get(r)
	if !ok {
		return nil, nil
	}
	user, err := u.opts.Accounts.GetUser(r.Context(), s.UserId)
	if errors.Is(err, account.ErrNotFound) {
		u.opts.Sessions.Destroy(w)
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if user.SecurityStamp != s.SecurityStamp || u.opts.Accounts.CanSignIn(user) != nil {
		u.opts.Sessions.Destroy(w)
		return nil, nil
	}
	return user, nil
}

// Login implements oauth.Interaction.
func (u *UI) Login(w http.ResponseWriter, r *http.Request, returnTo string) {
	u.redirect(w, r, u.url(PathLogin)+"?"+url.Values{"return_to": {returnTo}}.Encode())
}

// ConsentData is the data of the consent page.
type ConsentData struct {
	ClientName  string
	Description string
	Scopes      []string
	Action      string
	Params      url.Values
}

// Consent implements oauth.Interaction.
func (u *UI) Consent(w http.ResponseWriter, r *http.Request, req *oauth.ConsentRequest) {
	name := req.Client.Name
	if name == "" {
		name = req.Client.ClientId
	}
	u.render(w, r, http.StatusOK, "consent", &Page{
		Title: "Authorize " + name,
		User:  req.User,
		Data: &ConsentData{
			ClientName:  name,
			Description: req.Client.Description,
			Scopes:      req.Scopes,
			Action:      req.Action,
			Params:      req.Params,
		},
	})
}

// VerifyConsent implements oauth.Interaction.
func (u *UI) VerifyConsent(r *http.Request) bool {
	return u.opts.Sessions.VerifyCSRF(r)
}

// Error implements oauth.Interaction.
func (u *UI) Error(w http.ResponseWriter, r *http.Request, err *oauth.Error) {
	status := err.Status
	if status == 0 || status == http.StatusUnauthorized {
		status = http.StatusBadRequest
	}
	message := err.Description
	if message == "" {
		message = err.Code
	}
	u.message(w, r, status, "Authorization failed", "The authorization request is invalid: "+message+".")
}

func (u *UI) home(w http.ResponseWriter, r *http.Request) {
	user, err := u.CurrentUser(w, r)
	if err != nil {
		u.serverError(w, r, err)
		return
	}
	if user == nil {
		u.redirect(w, r, u.url(PathLogin))
		return
	}
	u.render(w, r, http.StatusOK, "home", &Page{Title: "Your account", User: user})
}

// LoginData is the data of the login page.
type LoginData struct {
	AllowRegistration bool
	ShowResend        bool
}

func (u *UI) loginPage(w http.ResponseWriter, r *http.Request) {
	returnTo := u.safeReturnTo(r.URL.Query().Get("return_to"))
	user, err := u.CurrentUser(w, r)
	if err != nil {
		u.serverError(w, r, err)
		return
	}
	if user != nil && r.URL.Query().Get("prompt") != "login" {
		u.redirect(w, r, returnTo)
		return
	}
	u.renderLogin(w, r, http.StatusOK, map[string]string{"return_to": returnTo}, "", false)
}

func (u *UI) renderLogin(w http.ResponseWriter, r *http.Request, status int, form map[string]string, errMsg string, showResend bool) {
	u.render(w, r, status, "login", &Page{
		Title: "Sign in",
		Error: errMsg,
		Form:  form,
		Data:  &LoginData{AllowRegistration: u.opts.AllowRegistration, ShowResend: showResend},
	})
}

func (u *UI) loginSubmit(w http.ResponseWriter, r *http.Request) {
	valid := u.verifyCSRF(w, r)
	login := strings.TrimSpace(r.PostForm.Get("login"))
	form := map[string]string{"login": login, "return_to": u.safeReturnTo(r.PostForm.Get("return_to"))}
	if !valid {
		u.renderLogin(w, r, http.StatusBadRequest, form, csrfMessage, false)
		return
	}

	user, err := u.opts.Accounts.Authenticate(r.Context(), login, r.PostForm.Get("password"))
	switch {
	case err == nil:
	case errors.Is(err, account.ErrInvalidCredentials):
		u.renderLogin(w, r, http.StatusUnauthorized, form, "Invalid username or password.", false)
		return
	case errors.Is(err, account.ErrLockedOut):
		u.renderLogin(w, r, http.StatusUnauthorized, form, "Your account is temporarily locked because of too many failed sign in attempts. Please try again later.", false)
		return
	case errors.Is(err, account.ErrDisabled):
		u.renderLogin(w, r, http.StatusUnauthorized, form, "Your account is disabled.", false)
		return
	case errors.Is(err, account.ErrNotActivated):
		u.renderLogin(w, r, http.StatusUnauthorized, form, "Your account is not activated yet. Please use the link in the activation email.", true)
		return
	default:
		u.serverError(w, r, err)
		return
	}

	u.opts.Sessions.Create(w, user.Id, user.SecurityStamp)
	u.redirect(w, r, form["return_to"])
}

func (u *UI) logoutPage(w http.ResponseWriter, r *http.Request) {
	user, err := u.CurrentUser(w, r)
	if err != nil {
		u.serverError(w, r, err)
		return
	}
	if user == nil {
		u.message(w, r, http.StatusOK, "Signed out", "You are signed out.", Link{u.url(PathLogin), "Sign in"})
		return
	}
	u.render(w, r, http.StatusOK, "logout", &Page{Title: "Sign out", User: user})
}

func (u *UI) logoutSubmit(w http.ResponseWriter, r *http.Request) {
	if !u.verifyCSRF(w, r) {
		u.render(w, r, http.StatusBadRequest, "logout", &Page{Title: "Sign out", Error: csrfMessage})
		return
	}
	u.opts.Sessions.Destroy(w)
	u.message(w, r, http.StatusOK, "Signed out", "You have been signed out.", Link{u.url(PathLogin), "Sign in again"})
}

// PasswordData is the data of the registration and password reset pages.
type PasswordData struct {
	MinPasswordLength int
}

func (u *UI) passwordData() *PasswordData {
	return &PasswordData{MinPasswordLength: u.opts.Accounts.Options().MinPasswordLength}
}

func (u *UI) registerPage(w http.ResponseWriter, r *http.Request) {
	u.render(w, r, http.StatusOK, "register", &Page{Title: "Create an account", Data: u.passwordData()})
}

func (u *UI) registerSubmit(w http.ResponseWriter, r *http.Request) {
	valid := u.verifyCSRF(w, r)
	form := map[string]string{
		"username": strings.TrimSpace(r.PostForm.Get("username")),
		"email":    strings.TrimSpace(r.PostForm.Get("email")),
	}
	fail := func(status int, msg string) {
		u.render(w, r, status, "register", &Page{Title: "Create an account", Error: msg, Form: form, Data: u.passwordData()})
	}
	if !valid {
		fail(http.StatusBadRequest, csrfMessage)
		return
	}
	password := r.PostForm.Get("password")
	if password != r.PostForm.Get("password_confirm") {
		fail(http.StatusBadRequest, "The passwords don't match.")
		return
	}
	_, err := u.opts.Accounts.Register(r.Context(), form["username"], form["email"], password)
	var validation *identity.ValidationError
	switch {
	case err == nil:
	case errors.As(err, &validation):
		fail(http.StatusBadRequest, capitalize(validation.Error())+".")
		return
	case errors.Is(err, account.ErrUserExists):
		fail(http.StatusConflict, "The username or email address is already in use.")
		return
	default:
		u.serverError(w, r, err)
		return
	}
	if u.opts.Accounts.Options().RequireActivation {
		u.message(w, r, http.StatusOK, "Check your email",
			"Your account has been created. We sent an activation link to "+form["email"]+". Please follow the link to activate your account.",
			Link{u.url(PathActivationResend), "Didn't receive the email?"})
		return
	}
	u.message(w, r, http.StatusOK, "Account created", "Your account has been created.", Link{u.url(PathLogin), "Sign in"})
}

func (u *UI) activate(w http.ResponseWriter, r *http.Request) {
	_, err := u.opts.Accounts.Activate(r.Context(), r.URL.Query().Get("token"))
	if errors.Is(err, account.ErrInvalidToken) {
		u.message(w, r, http.StatusBadRequest, "Activation failed", "The activation link is invalid or has expired.",
			Link{u.url(PathActivationResend), "Send a new activation link"})
		return
	}
	if err != nil {
		u.serverError(w, r, err)
		return
	}
	u.message(w, r, http.StatusOK, "Account activated", "Your account is activated. You can now sign in.", Link{u.url(PathLogin), "Sign in"})
}

// EmailFormData is the data of the email form page.
type EmailFormData struct {
	Intro  string
	Action string
	Button string
}

var resendData = &EmailFormData{
	Intro:  "Enter the email address of your account and we'll send you a new activation link.",
	Action: PathActivationResend,
	Button: "Send activation link",
}

func (u *UI) resendPage(w http.ResponseWriter, r *http.Request) {
	u.render(w, r, http.StatusOK, "email_form", &Page{Title: "Activate your account", Data: resendData})
}

func (u *UI) resendSubmit(w http.ResponseWriter, r *http.Request) {
	valid := u.verifyCSRF(w, r)
	email := strings.TrimSpace(r.PostForm.Get("email"))
	if !valid {
		u.render(w, r, http.StatusBadRequest, "email_form", &Page{Title: "Activate your account", Error: csrfMessage, Form: map[string]string{"email": email}, Data: resendData})
		return
	}
	if err := u.opts.Accounts.ResendActivation(r.Context(), email); err != nil {
		u.serverError(w, r, err)
		return
	}
	u.message(w, r, http.StatusOK, "Check your email",
		"If an account that is not activated yet exists for "+email+", we sent a new activation link to it.",
		Link{u.url(PathLogin), "Back to sign in"})
}

var forgotData = &EmailFormData{
	Intro:  "Enter the email address of your account and we'll send you a link to choose a new password.",
	Action: PathPasswordForgot,
	Button: "Send reset link",
}

func (u *UI) forgotPage(w http.ResponseWriter, r *http.Request) {
	u.render(w, r, http.StatusOK, "email_form", &Page{Title: "Forgot your password?", Data: forgotData})
}

func (u *UI) forgotSubmit(w http.ResponseWriter, r *http.Request) {
	valid := u.verifyCSRF(w, r)
	email := strings.TrimSpace(r.PostForm.Get("email"))
	if !valid {
		u.render(w, r, http.StatusBadRequest, "email_form", &Page{Title: "Forgot your password?", Error: csrfMessage, Form: map[string]string{"email": email}, Data: forgotData})
		return
	}
	if err := u.opts.Accounts.RequestPasswordReset(r.Context(), email); err != nil {
		u.serverError(w, r, err)
		return
	}
	u.message(w, r, http.StatusOK, "Check your email",
		"If an account exists for "+email+", we sent a link to reset the password.",
		Link{u.url(PathLogin), "Back to sign in"})
}

func (u *UI) invalidResetLink(w http.ResponseWriter, r *http.Request) {
	u.message(w, r, http.StatusBadRequest, "Reset your password", "The password reset link is invalid or has expired.",
		Link{u.url(PathPasswordForgot), "Request a new link"})
}

func (u *UI) resetPage(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	err := u.opts.Accounts.VerifyPasswordResetToken(r.Context(), token)
	if errors.Is(err, account.ErrInvalidToken) {
		u.invalidResetLink(w, r)
		return
	}
	if err != nil {
		u.serverError(w, r, err)
		return
	}
	u.render(w, r, http.StatusOK, "password_reset", &Page{Title: "Choose a new password", Form: map[string]string{"token": token}, Data: u.passwordData()})
}

func (u *UI) resetSubmit(w http.ResponseWriter, r *http.Request) {
	valid := u.verifyCSRF(w, r)
	form := map[string]string{"token": r.PostForm.Get("token")}
	fail := func(status int, msg string) {
		u.render(w, r, status, "password_reset", &Page{Title: "Choose a new password", Error: msg, Form: form, Data: u.passwordData()})
	}
	if !valid {
		fail(http.StatusBadRequest, csrfMessage)
		return
	}
	password := r.PostForm.Get("password")
	if password != r.PostForm.Get("password_confirm") {
		fail(http.StatusBadRequest, "The passwords don't match.")
		return
	}
	_, err := u.opts.Accounts.ResetPassword(r.Context(), form["token"], password)
	var validation *identity.ValidationError
	switch {
	case err == nil:
	case errors.As(err, &validation):
		fail(http.StatusBadRequest, capitalize(validation.Error())+".")
		return
	case errors.Is(err, account.ErrInvalidToken):
		u.invalidResetLink(w, r)
		return
	default:
		u.serverError(w, r, err)
		return
	}
	// Existing sessions are invalid now, remove the cookie of this browser too
	u.opts.Sessions.Destroy(w)
	u.message(w, r, http.StatusOK, "Password changed", "Your password has been changed. You can now sign in with your new password.",
		Link{u.url(PathLogin), "Sign in"})
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
