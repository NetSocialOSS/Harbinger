package middlewares

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/gtuk/discordwebhook"
)

const (
	colorRed = "16711680"
	title    = "🚨 Error Report 🚨"
)

var (
	sensitiveKeys = []string{"reporterID", "UserID", "session_id", "userId", "user_id", "modid"}
)

// statusRecorder captures the status code from the response
type statusRecorder struct {
	http.ResponseWriter
	statusCode int
}

func (rec *statusRecorder) WriteHeader(code int) {
	rec.statusCode = code
	rec.ResponseWriter.WriteHeader(code)
}

// DiscordErrorReport is a middleware that sends error reports to a Discord webhook
func DiscordErrorReport(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(rec, r)

		// Send error reports for status codes 400+ (excluding 401 & 403)
		if rec.statusCode >= 400 &&
			rec.statusCode != http.StatusUnauthorized &&
			rec.statusCode != http.StatusForbidden {
			if err := sendErrorReportToDiscord(rec.statusCode, r); err != nil {
				log.Printf("Failed to send error report to Discord: %v", err)
			}
		}
	})
}

// sendErrorReportToDiscord sends an error report to the Discord webhook
func sendErrorReportToDiscord(statusCode int, r *http.Request) error {
	webhookURL := configuration.BugReportWebhook
	if webhookURL == "" {
		return fmt.Errorf("webhook URL not set in configuration")
	}

	currentTime := time.Now().Format(time.RFC3339)
	redactedURL := redactSensitiveParameters(r.URL)
	statusText := http.StatusText(statusCode)
	description := fmt.Sprintf("A request resulted in an error with status code %d.", statusCode)

	embed := discordwebhook.Embed{
		Title:       ptr(title),
		Description: ptr(description),
		Fields: &[]discordwebhook.Field{
			{Name: ptr("Status Code"), Value: ptr(statusText)},
			{Name: ptr("Request URL"), Value: ptr(redactedURL)},
			{Name: ptr("Time"), Value: ptr(currentTime)},
			{Name: ptr("Environment"), Value: ptr(configuration.Environment)},
		},
		Color: ptr(colorRed),
	}

	message := discordwebhook.Message{
		Embeds: &[]discordwebhook.Embed{embed},
	}

	if err := discordwebhook.SendMessage(webhookURL, message); err != nil {
		return fmt.Errorf("error sending message to Discord webhook: %w", err)
	}

	return nil
}

// redactSensitiveParameters removes sensitive data from the URL
func redactSensitiveParameters(u *url.URL) string {
	query := u.Query()
	for _, key := range sensitiveKeys {
		if query.Has(key) {
			query.Set(key, "redacted")
		}
	}
	u.RawQuery = query.Encode()
	return u.String()
}

// ptr is a helper function to get a string pointer
func ptr(s string) *string {
	return &s
}
