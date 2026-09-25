package mail

import (
	"context"
	"strings"
	"testing"
)

func TestBuildPlain(t *testing.T) {
	data, err := Build("Identity <no-reply@example.com>", &Message{To: "user@example.com", Subject: "Héllo", Text: "Line 1\nLine 2"})
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	for _, expected := range []string{
		"From: Identity <no-reply@example.com>\r\n",
		"To: user@example.com\r\n",
		"Subject: =?utf-8?q?H=C3=A9llo?=\r\n",
		"Content-Type: text/plain; charset=utf-8\r\n",
		"@example.com>\r\n",
		"Line 1",
	} {
		if !strings.Contains(s, expected) {
			t.Errorf("expected %q in message:\n%s", expected, s)
		}
	}
}

func TestBuildMultipart(t *testing.T) {
	data, err := Build("no-reply@example.com", &Message{To: "user@example.com", Subject: "Hi", Text: "text", HTML: "<p>html</p>"})
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	if !strings.Contains(s, "multipart/alternative") || !strings.Contains(s, "text/html") || !strings.Contains(s, "<p>html</p>") {
		t.Fatalf("unexpected message:\n%s", s)
	}
}

func TestMemorySender(t *testing.T) {
	s := &MemorySender{}
	if s.Last() != nil {
		t.Fatal("expected no message")
	}
	s.Send(context.Background(), &Message{To: "a"})
	s.Send(context.Background(), &Message{To: "b"})
	if len(s.Messages()) != 2 || s.Last().To != "b" {
		t.Fatal("unexpected messages")
	}
}

func TestSMTPSenderValidation(t *testing.T) {
	s := NewSMTPSender(SMTPConfig{Host: "localhost", From: "a@example.com"})
	if err := s.Send(context.Background(), &Message{To: "x@example.com\r\nBcc: evil@example.com"}); err == nil {
		t.Fatal("expected header injection to be rejected")
	}
}
