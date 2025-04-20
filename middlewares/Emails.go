package middlewares

import (
	"errors"
	"net/smtp"
	"netsocial/types"
	"strconv"
	"sync"
)

type EmailData struct {
	From    string
	To      string
	Subject string
	Text    string
	Html    string
}

var (
	globalConfig types.Config
	configOnce   sync.Once
)

func SetConfig(config types.Config) error {
	var err error
	configOnce.Do(func() {
		if e := validateConfig(config); e != nil {
			globalConfig = types.Config{}
			err = e
			return
		}
		globalConfig = config
	})
	return err
}

func validateConfig(config types.Config) error {
	if config.SMTP.Host == "" || config.SMTP.Port == 0 || config.SMTP.Username == "" || config.SMTP.Password == "" {
		return errors.New("invalid SMTP configuration")
	}
	return nil
}

// SendEmail sends an email using the global SMTP configuration and email data
func SendEmail(emailData EmailData) error {
	// Ensure the global configuration is set
	if globalConfig.SMTP.Host == "" || globalConfig.SMTP.Port == 0 {
		return errors.New("SMTP configuration not set")
	}

	smtpAuth := smtp.PlainAuth("", globalConfig.SMTP.Username, globalConfig.SMTP.Password, globalConfig.SMTP.Host)
	msg := constructEmailMessage(emailData)
	smtpServerAddress := globalConfig.SMTP.Host + ":" + strconv.Itoa(globalConfig.SMTP.Port)

	return smtp.SendMail(smtpServerAddress, smtpAuth, emailData.From, []string{emailData.To}, []byte(msg))
}

func constructEmailMessage(emailData EmailData) string {
	boundary := "boundary"
	header := "From: " + emailData.From + "\n" +
		"To: " + emailData.To + "\n" +
		"Subject: " + emailData.Subject + "\n" +
		"MIME-Version: 1.0\n" +
		"Content-Type: multipart/alternative; boundary=" + boundary + "\n\n"

	body := "--" + boundary + "\n" +
		"Content-Type: text/plain; charset=UTF-8\n\n" +
		emailData.Text + "\n\n" +
		"--" + boundary + "\n" +
		"Content-Type: text/html; charset=UTF-8\n\n" +
		emailData.Html + "\n\n" +
		"--" + boundary + "--"

	return header + body
}
