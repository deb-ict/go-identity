// Package mail sends the account emails (activation, password reset).
package mail

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/smtp"
	"net/textproto"
	"strings"
	"sync"
	"time"

	"github.com/deb-ict/go-identity/pkg/security"
)

// Message is an email message. Text is required, HTML is optional.
type Message struct {
	To      string
	Subject string
	Text    string
	HTML    string
}

// Sender sends email messages.
type Sender interface {
	Send(ctx context.Context, msg *Message) error
}

// SenderFunc adapts a function to the Sender interface.
type SenderFunc func(ctx context.Context, msg *Message) error

func (f SenderFunc) Send(ctx context.Context, msg *Message) error {
	return f(ctx, msg)
}

// LogSender logs the messages instead of sending them. Useful for development.
type LogSender struct {
	Logger *slog.Logger
}

func (s *LogSender) Send(ctx context.Context, msg *Message) error {
	logger := s.Logger
	if logger == nil {
		logger = slog.Default()
	}
	logger.InfoContext(ctx, "email", "to", msg.To, "subject", msg.Subject, "body", msg.Text)
	return nil
}

// MemorySender keeps the messages in memory. Useful for tests.
type MemorySender struct {
	mu       sync.Mutex
	messages []*Message
}

func (s *MemorySender) Send(ctx context.Context, msg *Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	copy := *msg
	s.messages = append(s.messages, &copy)
	return nil
}

// Messages returns the sent messages.
func (s *MemorySender) Messages() []*Message {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*Message{}, s.messages...)
}

// Last returns the last message sent, or nil.
func (s *MemorySender) Last() *Message {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.messages) == 0 {
		return nil
	}
	return s.messages[len(s.messages)-1]
}

// SMTPConfig configures the SMTP sender.
type SMTPConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	// ImplicitTLS connects with TLS directly (port 465). Otherwise STARTTLS is used when offered.
	ImplicitTLS bool
	// RequireTLS fails when the server doesn't offer STARTTLS.
	RequireTLS bool
	Timeout    time.Duration
}

// SMTPSender sends messages with SMTP.
type SMTPSender struct {
	Config SMTPConfig
}

func NewSMTPSender(config SMTPConfig) *SMTPSender {
	if config.Port == 0 {
		config.Port = 587
	}
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}
	return &SMTPSender{Config: config}
}

func (s *SMTPSender) Send(ctx context.Context, msg *Message) error {
	cfg := s.Config
	if cfg.Host == "" || cfg.From == "" {
		return errors.New("mail: smtp host and from address are required")
	}
	if strings.ContainsAny(msg.To, "\r\n") || strings.ContainsAny(cfg.From, "\r\n") {
		return errors.New("mail: invalid address")
	}
	data, err := Build(cfg.From, msg)
	if err != nil {
		return err
	}

	addr := net.JoinHostPort(cfg.Host, fmt.Sprint(cfg.Port))
	dialer := &net.Dialer{Timeout: cfg.Timeout}
	var conn net.Conn
	if cfg.ImplicitTLS {
		conn, err = (&tls.Dialer{NetDialer: dialer, Config: &tls.Config{ServerName: cfg.Host}}).DialContext(ctx, "tcp", addr)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	} else {
		conn.SetDeadline(time.Now().Add(cfg.Timeout))
	}

	client, err := smtp.NewClient(conn, cfg.Host)
	if err != nil {
		conn.Close()
		return err
	}
	defer client.Close()

	if !cfg.ImplicitTLS {
		if ok, _ := client.Extension("STARTTLS"); ok {
			if err := client.StartTLS(&tls.Config{ServerName: cfg.Host}); err != nil {
				return err
			}
		} else if cfg.RequireTLS {
			return errors.New("mail: smtp server doesn't support STARTTLS")
		}
	}
	if cfg.Username != "" {
		if err := client.Auth(smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)); err != nil {
			return err
		}
	}
	if err := client.Mail(cfg.From); err != nil {
		return err
	}
	if err := client.Rcpt(msg.To); err != nil {
		return err
	}
	w, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(data); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return client.Quit()
}

// Build renders the message in RFC 5322 format.
func Build(from string, msg *Message) ([]byte, error) {
	var buf bytes.Buffer
	header := func(k, v string) {
		buf.WriteString(k + ": " + v + "\r\n")
	}
	header("From", from)
	header("To", msg.To)
	header("Subject", mime.QEncoding.Encode("utf-8", msg.Subject))
	header("Date", time.Now().Format(time.RFC1123Z))
	header("Message-ID", "<"+security.RandomToken(16)+"@"+domainOf(from)+">")
	header("MIME-Version", "1.0")

	if msg.HTML == "" {
		header("Content-Type", "text/plain; charset=utf-8")
		header("Content-Transfer-Encoding", "quoted-printable")
		buf.WriteString("\r\n")
		if err := writeQuotedPrintable(&buf, msg.Text); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	}

	mw := multipart.NewWriter(&buf)
	header("Content-Type", "multipart/alternative; boundary="+mw.Boundary())
	buf.WriteString("\r\n")
	for _, part := range []struct{ contentType, body string }{
		{"text/plain; charset=utf-8", msg.Text},
		{"text/html; charset=utf-8", msg.HTML},
	} {
		w, err := mw.CreatePart(textproto.MIMEHeader{
			"Content-Type":              {part.contentType},
			"Content-Transfer-Encoding": {"quoted-printable"},
		})
		if err != nil {
			return nil, err
		}
		if err := writeQuotedPrintable(w, part.body); err != nil {
			return nil, err
		}
	}
	if err := mw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeQuotedPrintable(w interface{ Write([]byte) (int, error) }, body string) error {
	qp := quotedprintable.NewWriter(w)
	if _, err := qp.Write([]byte(body)); err != nil {
		return err
	}
	return qp.Close()
}

func domainOf(address string) string {
	address = strings.TrimSuffix(address, ">")
	if i := strings.LastIndex(address, "@"); i >= 0 {
		return address[i+1:]
	}
	return "localhost"
}
