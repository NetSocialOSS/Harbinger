package middlewares

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/gtuk/discordwebhook"
)

// DiscordErrorReport is a middleware that sends error reports to a Discord webhook
func DiscordErrorReport(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, statusCode: http.StatusOK}

		// Call the next handler
		next.ServeHTTP(rec, r)

		// If there was an error (status code is 400 or higher, excluding 401 and 403), send a report to Discord
		if rec.statusCode >= 400 && rec.statusCode != http.StatusUnauthorized && rec.statusCode != http.StatusForbidden {
			if err := sendErrorReportToDiscord(rec.statusCode, r); err != nil {
				log.Printf("Failed to send error report to Discord: %v", err)
			}
		}
	})
}

// statusRecorder is a custom ResponseWriter to capture the status code
type statusRecorder struct {
	http.ResponseWriter
	statusCode int
}

func (rec *statusRecorder) WriteHeader(code int) {
	// Always record the status code, not just when it's 200
	rec.statusCode = code
	rec.ResponseWriter.WriteHeader(code)
}

// sendErrorReportToDiscord sends a detailed error report to the configured Discord webhook
func sendErrorReportToDiscord(statusCode int, r *http.Request) error {
	webhookURL := os.Getenv("DISCORD_BUG_REPORT_WEBHOOK_URL")
	if webhookURL == "" {
		return fmt.Errorf("webhook URL not set in environment variables")
	}
	color := "16711680"
	title := "🚨 Error Report 🚨"
	description := fmt.Sprintf("A request resulted in an error with status code %d.", statusCode)
	statusText := http.StatusText(statusCode)
	redactedURL := redactSensitiveParameters(r.URL)
	currentTime := time.Now().Format(time.RFC3339)

	embed := discordwebhook.Embed{
		Title:       &title,
		Description: &description,
		Fields: &[]discordwebhook.Field{
			{
				Name:  ptr("Status Code"),
				Value: &statusText,
			},
			{
				Name:  ptr("Request URL"),
				Value: &redactedURL,
			},
			{
				Name:  ptr("Time"),
				Value: &currentTime,
			},
		},
		Color: &color,
	}

	message := discordwebhook.Message{
		Embeds: &[]discordwebhook.Embed{embed},
	}

	// Send the message to Discord
	if err := discordwebhook.SendMessage(webhookURL, message); err != nil {
		return fmt.Errorf("error sending message to Discord webhook: %w", err)
	}

	return nil
}

// redactSensitiveParameters redacts sensitive query parameters from the URL
func redactSensitiveParameters(u *url.URL) string {
	query := u.Query()
	sensitiveKeys := []string{"reporterID", "UserID", "session_id", "userId", "user_id", "modid"}

	for _, key := range sensitiveKeys {
		if query.Has(key) {
			query.Set(key, "redacted")
		}
	}

	u.RawQuery = query.Encode()
	return u.String()
}

// ptr is a helper function to convert a string to a pointer
func ptr(s string) *string {
	return &s
}
