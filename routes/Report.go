package routes

import (
	"context"
	"fmt"
	"net/http"
	"netsocial/database"
	"netsocial/middlewares"
	"netsocial/types"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gtuk/discordwebhook"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
)

var config types.Config
var webhookURL string

// getReporterUsername fetches the reporter's username from the database
func getReporterUsername(ctx context.Context, db *pgxpool.Pool, reporterID string) (string, error) {
	query := "SELECT username FROM users WHERE id = $1"
	var username string
	err := db.QueryRow(ctx, query, reporterID).Scan(&username)
	if err != nil {
		if err == pgx.ErrNoRows {
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
	encrypteduserId := r.Header.Get("X-userID")
	if encrypteduserId == "" {
		http.Error(w, "userId query parameter is required", http.StatusBadRequest)
		return
	}

	reporterID, err := middlewares.DecryptAES(encrypteduserId)
	if err != nil {
		http.Error(w, "Failed to decrypt userid", http.StatusBadRequest)
		return
	}

	db := r.Context().Value(database.DBContextKey).(*pgxpool.Pool)
	reporterUsername, err := getReporterUsername(r.Context(), db, reporterID)
	if err != nil {
		http.Error(w, `{"error": "Failed to fetch reporter username"}`, http.StatusInternalServerError)
		return
	}

	if reporterUsername == "" {
		http.Error(w, `{"error": "Invalid reporter ID"}`, http.StatusBadRequest)
		return
	}

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
	encrypteduserId := r.Header.Get("X-userID")
	if encrypteduserId == "" {
		http.Error(w, "userId query parameter is required", http.StatusBadRequest)
		return
	}

	reporterID, err := middlewares.DecryptAES(encrypteduserId)
	if err != nil {
		http.Error(w, "Failed to decrypt userid", http.StatusBadRequest)
		return
	}

	db := r.Context().Value(database.DBContextKey).(*pgxpool.Pool)
	reporterUsername, err := getReporterUsername(r.Context(), db, reporterID)
	if err != nil {
		http.Error(w, `{"error": "Failed to fetch reporter username"}`, http.StatusInternalServerError)
		return
	}

	if reporterUsername == "" {
		http.Error(w, `{"error": "Invalid reporter ID"}`, http.StatusBadRequest)
		return
	}

	query := "SELECT id FROM post WHERE id = $1"
	var postID string
	err = db.QueryRow(r.Context(), query, reportedPostID).Scan(&postID)
	if err != nil {
		if err == pgx.ErrNoRows {
			http.Error(w, `{"error": "Invalid reported post ID"}`, http.StatusBadRequest)
			return
		}
		http.Error(w, "Failed to check post existence", http.StatusInternalServerError)
		return
	}

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
	coterieName := r.URL.Query().Get("coterie")
	reason := r.URL.Query().Get("reason")

	encrypteduserId := r.Header.Get("X-userID")
	if encrypteduserId == "" {
		http.Error(w, "userId query parameter is required", http.StatusBadRequest)
		return
	}

	reporterID, err := middlewares.DecryptAES(encrypteduserId)
	if err != nil {
		http.Error(w, "Failed to decrypt userid", http.StatusBadRequest)
		return
	}

	db := r.Context().Value(database.DBContextKey).(*pgxpool.Pool)
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
	err = db.QueryRow(r.Context(), query, coterieName).Scan(&name)
	if err != nil {
		if err == pgx.ErrNoRows {
			http.Error(w, `{"error": "Invalid reported coterie name"}`, http.StatusBadRequest)
			return
		}
		http.Error(w, "Failed to check coterie existence", http.StatusInternalServerError)
		return
	}

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
	r.With(RateLimit(5, 5*time.Minute)).Post("/report/user", ReportUser)
	r.With(RateLimit(5, 5*time.Minute)).Post("/report/post", ReportPost)
	r.With(RateLimit(5, 5*time.Minute)).Post("/report/coterie", ReportCoterie)
}
