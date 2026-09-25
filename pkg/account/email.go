package account

import (
	"bytes"
	"fmt"
	"html/template"
	"time"

	"github.com/deb-ict/go-identity/pkg/identity"
	"github.com/deb-ict/go-identity/pkg/mail"
)

var htmlEmail = template.Must(template.New("email").Parse(`<!DOCTYPE html>
<html><body style="font-family: sans-serif; color: #1f2937;">
<h2>{{.Title}}</h2>
<p>Hello {{.Username}},</p>
<p>{{.Intro}}</p>
<p><a href="{{.Link}}" style="display: inline-block; padding: 10px 18px; background: #2563eb; color: #fff; text-decoration: none; border-radius: 6px;">{{.Action}}</a></p>
<p>This link expires in {{.Expires}}. {{.Outro}}</p>
<p style="color: #6b7280; font-size: 12px;">{{.Link}}</p>
</body></html>`))

type emailData struct {
	Title, Username, Intro, Action, Link, Expires, Outro string
}

func buildMessage(user *identity.User, subject string, data emailData) *mail.Message {
	var html bytes.Buffer
	htmlEmail.Execute(&html, data)
	text := fmt.Sprintf("Hello %s,\n\n%s\n\n%s: %s\n\nThis link expires in %s. %s\n",
		data.Username, data.Intro, data.Action, data.Link, data.Expires, data.Outro)
	return &mail.Message{
		To:      user.Email,
		Subject: subject,
		Text:    text,
		HTML:    html.String(),
	}
}

func formatDuration(d time.Duration) string {
	switch {
	case d%(24*time.Hour) == 0:
		n := int(d / (24 * time.Hour))
		if n == 1 {
			return "1 day"
		}
		return fmt.Sprintf("%d days", n)
	case d%time.Hour == 0:
		n := int(d / time.Hour)
		if n == 1 {
			return "1 hour"
		}
		return fmt.Sprintf("%d hours", n)
	default:
		return fmt.Sprintf("%d minutes", int(d.Minutes()))
	}
}

func activationMessage(appName string, user *identity.User, link string, lifetime time.Duration) *mail.Message {
	return buildMessage(user, appName+": activate your account", emailData{
		Title:    "Activate your account",
		Username: user.Username,
		Intro:    "Thank you for signing up. Please confirm your email address to activate your account.",
		Action:   "Activate account",
		Link:     link,
		Expires:  formatDuration(lifetime),
		Outro:    "If you didn't create an account, you can ignore this email.",
	})
}

func passwordResetMessage(appName string, user *identity.User, link string, lifetime time.Duration) *mail.Message {
	return buildMessage(user, appName+": reset your password", emailData{
		Title:    "Reset your password",
		Username: user.Username,
		Intro:    "We received a request to reset the password of your account.",
		Action:   "Choose a new password",
		Link:     link,
		Expires:  formatDuration(lifetime),
		Outro:    "If you didn't request a password reset, you can ignore this email.",
	})
}
