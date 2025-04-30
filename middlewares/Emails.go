package middlewares

import (
	"errors"
	"fmt"
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
	// Accept either username/password or access token for ms360
	if config.SMTP.Host == "" || config.SMTP.Port == 0 {
		return errors.New("invalid SMTP configuration")
	}
	if config.SMTP.AccessToken == "" && (config.SMTP.Username == "" || config.SMTP.Password == "") {
		return errors.New("SMTP configuration must have either access token or username/password")
	}
	return nil
}

// SendEmail sends an email using the global SMTP configuration and email data
func SendEmail(emailData EmailData) error {
	// Ensure the global configuration is set
	if globalConfig.SMTP.Host == "" || globalConfig.SMTP.Port == 0 {
		return errors.New("SMTP configuration not set")
	}

	var smtpAuth smtp.Auth
	if globalConfig.SMTP.AccessToken != "" {
		// Use XOAUTH2 for ms360
		smtpAuth = OAuth2Auth(globalConfig.SMTP.Username, globalConfig.SMTP.AccessToken)
	} else {
		smtpAuth = smtp.PlainAuth("", globalConfig.SMTP.Username, globalConfig.SMTP.Password, globalConfig.SMTP.Host)
	}
	msg := constructEmailMessage(emailData)
	smtpServerAddress := globalConfig.SMTP.Host + ":" + strconv.Itoa(globalConfig.SMTP.Port)

	return smtp.SendMail(smtpServerAddress, smtpAuth, emailData.From, []string{emailData.To}, []byte(msg))
}

// OAuth2Auth returns an smtp.Auth implementation for XOAUTH2 (ms360)
func OAuth2Auth(username, accessToken string) smtp.Auth {
	return &oauth2Auth{username, accessToken}
}

type oauth2Auth struct {
	username    string
	accessToken string
}

func (a *oauth2Auth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	// XOAUTH2 format: base64("user=<user>\x01auth=Bearer <token>\x01\x01")
	authString := fmt.Sprintf("user=%s\x01auth=Bearer %s\x01\x01", a.username, a.accessToken)
	return "XOAUTH2", []byte(authString), nil
}

func (a *oauth2Auth) Next(fromServer []byte, more bool) ([]byte, error) {
	return nil, nil
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
