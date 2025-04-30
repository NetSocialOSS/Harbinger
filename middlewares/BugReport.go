package middlewares

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gtuk/discordwebhook"
)

const (
	colorRed = "16711680"
	title    = "🚨 Error Report 🚨"
)

var (
	sensitiveKeys = []string{"reporterID", "UserID", "session_id", "userId", "user_id", "modid"}
	// Add status codes to ignore
	ignoredStatusCodes = map[int]struct{}{
		http.StatusNotFound:                   {}, // 404
		http.StatusGone:                       {}, // 410
		http.StatusTooManyRequests:            {}, // 429
		http.StatusUnauthorized:               {}, // 401
		http.StatusForbidden:                  {}, // 403
		http.StatusMovedPermanently:           {}, // 301
		http.StatusFound:                      {}, // 302
		http.StatusTemporaryRedirect:          {}, // 307
		http.StatusPermanentRedirect:          {}, // 308
		http.StatusMethodNotAllowed:           {}, // 405
		http.StatusBadRequest:                 {}, // 400
		http.StatusUnavailableForLegalReasons: {}, // 451
		http.StatusUnprocessableEntity:        {}, // 422
		418:                                   {}, // I'm a teapot
	}
	ignoredPaths = []string{"/robots.txt"}
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

		// Ignore certain status codes
		if _, ok := ignoredStatusCodes[rec.statusCode]; ok {
			return
		}
		// Ignore certain paths (e.g., robots.txt)
		for _, p := range ignoredPaths {
			if strings.EqualFold(r.URL.Path, p) {
				return
			}
		}
		// Only report errors for status codes 400+ (excluding ignored)
		if rec.statusCode >= 400 {
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
