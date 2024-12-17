package routes

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"netsocial/middlewares"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gtuk/discordwebhook"
)

// getReporterUsername fetches the reporter's username from the database
func getReporterUsername(ctx context.Context, db *sql.DB, reporterID string) (string, error) {
	query := "SELECT username FROM users WHERE id = $1"
	var username string
	err := db.QueryRowContext(ctx, query, reporterID).Scan(&username)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", nil
		}
		return "", fmt.Errorf("error fetching reporter username: %v", err)
	}
	return username, nil
}

// ReportUser handles reporting a user
func ReportUser(w http.ResponseWriter, r *http.Request) {
	reportedUsername := r.URL.Query().Get("reportedUsername")
	reason := r.URL.Query().Get("reason")
	encryptedreporterID := r.Header.Get("X-userID")

	reporterID, err := middlewares.DecryptAES(encryptedreporterID)
	if err != nil {
		http.Error(w, "Failed to decrypt userid", http.StatusBadRequest)
		return
	}

	db := r.Context().Value("db").(*sql.DB)
	reporterUsername, err := getReporterUsername(r.Context(), db, reporterID)
	if err != nil {
		http.Error(w, `{"error": "Failed to fetch reporter username"}`, http.StatusInternalServerError)
		return
	}

	if reporterUsername == "" {
		http.Error(w, `{"error": "Invalid reporter ID"}`, http.StatusBadRequest)
		return
	}

	webhookURL := os.Getenv("Report_URL")

	title := "User Report"
	description := fmt.Sprintf("[Reported User: %s](https://netsocial.app/user/%s)", reportedUsername, reportedUsername)
	reporterUsernameField := "Reporter"
	reasonField := "Reason"

	embed := discordwebhook.Embed{
		Title:       &title,
		Description: &description,
		Fields: &[]discordwebhook.Field{
			{
				Name:  &reporterUsernameField,
				Value: &reporterUsername,
			},
			{
				Name:  &reasonField,
				Value: &reason,
			},
		},
	}

	content := fmt.Sprintf("User %s has been reported by %s for reason: %s", reportedUsername, reporterUsername, reason)
	message := discordwebhook.Message{
		Content: &content,
		Embeds:  &[]discordwebhook.Embed{embed},
	}

	err = discordwebhook.SendMessage(webhookURL, message)
	if err != nil {
		http.Error(w, "Failed to report user", http.StatusInternalServerError)
		return
	}

	w.Write([]byte("User reported successfully"))
}

// ReportPost handles reporting a post
func ReportPost(w http.ResponseWriter, r *http.Request) {
	reportedPostID := r.URL.Query().Get("reportedPostID")
	reason := r.URL.Query().Get("reason")
	encryptedreporterID := r.Header.Get("X-userID")

	reporterID, err := middlewares.DecryptAES(encryptedreporterID)
	if err != nil {
		http.Error(w, "Failed to decrypt userid", http.StatusBadRequest)
		return
	}

	db := r.Context().Value("db").(*sql.DB)
	reporterUsername, err := getReporterUsername(r.Context(), db, reporterID)
	if err != nil {
		http.Error(w, `{"error": "Failed to fetch reporter username"}`, http.StatusInternalServerError)
		return
	}

	if reporterUsername == "" {
		http.Error(w, `{"error": "Invalid reporter ID"}`, http.StatusBadRequest)
		return
	}

	query := "SELECT id FROM Post WHERE id = $1"
	var postID string
	err = db.QueryRowContext(r.Context(), query, reportedPostID).Scan(&postID)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, `{"error": "Invalid reported post ID"}`, http.StatusBadRequest)
			return
		}
		http.Error(w, "Failed to check post existence", http.StatusInternalServerError)
		return
	}

	webhookURL := os.Getenv("Report_URL")

	title := "Post Report"
	description := fmt.Sprintf("[Reported Post](https://netsocial.app/post/%s)", reportedPostID)
	reporterUsernameField := "Reporter"
	reasonField := "Reason"

	embed := discordwebhook.Embed{
		Title:       &title,
		Description: &description,
		Fields: &[]discordwebhook.Field{
			{
				Name:  &reporterUsernameField,
				Value: &reporterUsername,
			},
			{
				Name:  &reasonField,
				Value: &reason,
			},
		},
	}

	content := fmt.Sprintf("Post %s has been reported by %s for reason: %s", reportedPostID, reporterUsername, reason)
	message := discordwebhook.Message{
		Content: &content,
		Embeds:  &[]discordwebhook.Embed{embed},
	}

	err = discordwebhook.SendMessage(webhookURL, message)
	if err != nil {
		http.Error(w, "Failed to report post", http.StatusInternalServerError)
		return
	}

	w.Write([]byte("Post reported successfully"))
}

// ReportCoterie handles reporting a coterie
func ReportCoterie(w http.ResponseWriter, r *http.Request) {
	coterieName := r.URL.Query().Get("Coterie")
	reason := r.URL.Query().Get("reason")
	encryptedreporterID := r.Header.Get("X-userID")

	reporterID, err := middlewares.DecryptAES(encryptedreporterID)
	if err != nil {
		http.Error(w, "Failed to decrypt userid", http.StatusBadRequest)
		return
	}

	db := r.Context().Value("db").(*sql.DB)
	reporterUsername, err := getReporterUsername(r.Context(), db, reporterID)
	if err != nil {
		http.Error(w, `{"error": "Failed to fetch reporter username"}`, http.StatusInternalServerError)
		return
	}

	if reporterUsername == "" {
		http.Error(w, `{"error": "Invalid reporter ID"}`, http.StatusBadRequest)
		return
	}

	query := "SELECT name FROM coterie WHERE name = $1"
	var name string
	err = db.QueryRowContext(r.Context(), query, coterieName).Scan(&name)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, `{"error": "Invalid reported coterie name"}`, http.StatusBadRequest)
			return
		}
		http.Error(w, "Failed to check coterie existence", http.StatusInternalServerError)
		return
	}

	webhookURL := os.Getenv("Report_URL")

	title := "🚨 Coterie Report 🚨"
	description := fmt.Sprintf("[Reported Coterie](https://netsocial.app/coterie/%s)", coterieName)
	reporterUsernameField := "Reporter"
	reasonField := "Reason"

	embed := discordwebhook.Embed{
		Title:       &title,
		Description: &description,
		Fields: &[]discordwebhook.Field{
			{
				Name:  &reporterUsernameField,
				Value: &reporterUsername,
			},
			{
				Name:  &reasonField,
				Value: &reason,
			},
		},
	}

	content := fmt.Sprintf("Coterie %s has been reported by %s for reason: %s", coterieName, reporterUsername, reason)
	message := discordwebhook.Message{
		Content: &content,
		Embeds:  &[]discordwebhook.Embed{embed},
	}

	err = discordwebhook.SendMessage(webhookURL, message)
	if err != nil {
		http.Error(w, "Failed to report coterie", http.StatusInternalServerError)
		return
	}

	w.Write([]byte("Coterie reported successfully"))
}

func Report(r chi.Router) {
	r.With(RateLimit(5, 5*time.Minute)).Post("/report/user", (middlewares.DiscordErrorReport(http.HandlerFunc(ReportUser))).ServeHTTP)
	r.With(RateLimit(5, 5*time.Minute)).Post("/report/post", (middlewares.DiscordErrorReport(http.HandlerFunc(ReportPost))).ServeHTTP)
	r.With(RateLimit(5, 5*time.Minute)).Post("/report/coterie", (middlewares.DiscordErrorReport(http.HandlerFunc(ReportCoterie)).ServeHTTP))
}
