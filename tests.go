package main

import (
	"log/slog"

	"github.com/gin-gonic/gin"
	"gopkg.in/gomail.v2"
)

func test_endpoints(s *Settings, eng *gin.Engine) {
		eng.POST("/internal/send-test-email-queue", SendTestEmail_queue(s))
		eng.POST("/internal/send-test-email-simple", SendTestEmail_simple(s))
}

//This is for testing and benchmarking against the performance from the db

func SendTestEmail_queue(s *Settings) gin.HandlerFunc {
	return func(c *gin.Context) {
		var err		error
		var req		struct {
			Email		string `json:"email"`
		}

		err = c.ShouldBindBodyWithJSON(&req)
		if err != nil {
			slog.Error("Failed to decode body")
			return
		}
		m := gomail.NewMessage()
		m.SetHeader("To", req.Email)
		m.SetHeader("From", s.Mail.User)
		m.SetHeader("Subject", "Test")
		s.Mail.Enqueue(m)
	}
}

func SendTestEmail_simple(s *Settings) gin.HandlerFunc {
	return func(c *gin.Context) {
		var err		error
		var req		struct {
			Email		string `json:"email"`
		}

		err = c.ShouldBindBodyWithJSON(&req)
		if err != nil {
			slog.Error("Failed to decode body")
			return
		}
		m := gomail.NewMessage()
		m.SetHeader("To", req.Email)
		m.SetHeader("From", s.Mail.User)
		m.SetHeader("Subject", "Test")
		d := gomail.NewDialer(s.Mail.Provider, 587, s.Mail.User, s.Mail_key)
		err = d.DialAndSend(m)
		if err != nil {
			slog.Error("failed to send email", "to", m.GetHeader("To"), "err", err)
		}
	}
}
