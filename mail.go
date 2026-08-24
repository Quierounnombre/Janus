package main

import (
	"bytes"
	"embed"
	"errors"
	"html/template"
	"log/slog"
	"time"

	"gopkg.in/gomail.v2"
)

// DON'T REMOVE THE UNDERLAYING COMMENT

//go:embed templates/*.html
var templateFS	embed.FS
var tmpls		*template.Template

// May need hardening when sending emails, could be abuse to launch 10x
func init_mail(s *Settings) {
	s.Mail.dialer = gomail.NewDialer(s.Mail.Provider, s.Mail.Port, s.Mail.User, s.Mail_key)
	s.Mail.queue = make(chan *gomail.Message, s.Mail.Queue_size)
	s.Mail.retry_queue = make(chan *gomail.Message, s.Mail.Queue_size)
	go s.Mail.Manager()
}

func (mr *Mail_settings)Enqueue(m *gomail.Message) error {
	//Added protection from heavy load
	select {
		case mr.queue <- m:
			return nil
		default:
			return errors.New("mail queue full")
	}
}

//Could be overloaded, in a VERY especific case, may need extra protection
func (mr *Mail_settings)Retry_Enqueue(m *gomail.Message) {
	mr.retry_queue <- m
}

func (mr *Mail_settings)run(stop chan struct{}) {
	var s		gomail.SendCloser
	var err		error

	for {
		select {
		case m := <-mr.queue:
			if s == nil {
				s, err = mr.dialer.Dial()
				if err != nil {
					slog.Error("smtp failed to dial", "err", err)
					time.AfterFunc(5*time.Second, func() { mr.Enqueue(m) })
					continue
				}
			}
			err := gomail.Send(s, m)
			if err != nil {
				time.AfterFunc(5*time.Second, func() { mr.Retry_Enqueue(m) })
				slog.Error("send failed", "err", err)
				s.Close()
				s = nil
			}
		case m := <-mr.retry_queue:
			if s == nil {
				s, err = mr.dialer.Dial()
				if err != nil {
					slog.Error("smtp failed to dial", "err", err)
					slog.Error("dropped email", "to", m.GetHeader("To"))
					continue
				}
			}
			err := gomail.Send(s, m)
			if err != nil {
				slog.Error("send failed", "err", err)
				slog.Error("dropped email", "to", m.GetHeader("To"))
				s.Close()
				s = nil }
		case <-stop:
			if s != nil {
				s.Close()
			}
			return
		}
	}
}

func (mr *Mail_settings)Manager() {
	var stop		chan struct{}
	var n_workers	int
	var ex_wk		int

	stop = make(chan struct{})
	n_workers = 0
	ex_wk = 0
	for {
		queue_size := len(mr.queue)
		ex_wk = (queue_size + mr.Worker_per_qeueu - 1) / mr.Worker_per_qeueu
		if n_workers <= ex_wk {
			if n_workers <= mr.Max_workers {
				slog.Info("Email worker created", "Email backlog", queue_size, "ex_wk", ex_wk)
				go mr.run(stop)
				n_workers += 1
			}
		} else if n_workers > mr.Min_workers {
			slog.Info("Email worker deleted", "Email backlog", queue_size, "ex_wk", ex_wk)
			stop <- struct{}{}
			n_workers -= 1
		}
		time.Sleep(mr.Sleep_time)
	}
}

//TODO: Personalized HTML for each purpose from 2FA
func resetPasswordHTML(link string) (string, error) {
	var buf		bytes.Buffer
	var err		error

	err = tmpls.ExecuteTemplate(&buf, "reset_pass.html", struct{ Link string }{ link })
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

func TwoFA_Mail(s *Settings, db *Db_data, target string, id string) error {
	var err		error

	m := gomail.NewMessage()
	m.SetHeader("From", s.Mail.From)
	m.SetHeader("To", target)
	m.SetHeader("Subject", "Doble factor de autentificación")
	str, err := TwoFAHTML(s.Frontend + "/2FA_validate/" + id)
	if err != nil {
		return err
	}
	m.SetBody("text/html", str)
	err = s.Mail.Enqueue(m)
	if err != nil {
		return err
	}
	return nil
}

func TwoFAHTML(link string) (string, error) {
	var buf		bytes.Buffer
	var err		error

	err = tmpls.ExecuteTemplate(&buf, "2FA_validate.html", struct{ Link string }{ link })
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}
