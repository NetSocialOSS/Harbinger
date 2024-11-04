package routes

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"netsocial/middlewares"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gtuk/discordwebhook"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

// getReporterUsername fetches the reporter's username from the database
func getReporterUsername(ctx context.Context, db *mongo.Client, reporterID string) (string, error) {
	userCollection := db.Database("SocialFlux").Collection("users")

	// Convert reporterID string to ObjectID
	objID, err := primitive.ObjectIDFromHex(reporterID)
	if err != nil {
		return "", fmt.Errorf("invalid reporter ID format")
	}

	filter := bson.M{"_id": objID}

	var result struct {
		Username string `bson:"username"`
	}
	err = userCollection.FindOne(ctx, filter).Decode(&result)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return "", nil
		}
		return "", err
	}

	return result.Username, nil
}

// ReportUser handles reporting a user
func ReportUser(w http.ResponseWriter, r *http.Request) {
	reportedUsername := r.URL.Query().Get("reportedUsername")
	reporterID := r.URL.Query().Get("reporterID")
	reason := r.URL.Query().Get("reason")

	db := r.Context().Value("db").(*mongo.Client)
	reporterUsername, err := getReporterUsername(r.Context(), db, reporterID)
	if err != nil {
		log.Println("Error fetching reporter username:", err)
		http.Error(w, `{"error": "Failed to fetch reporter username"}`, http.StatusInternalServerError)
		return
	}

	if reporterUsername == "" {
		http.Error(w, `{"error": "Invalid reporter ID"}`, http.StatusBadRequest)
		return
	}

	webhookURL := os.Getenv("Report_URL")

	title := "🚨 User Report 🚨"
	description := fmt.Sprintf("[Reported User: %s](https://netsocial.app/user/%s)", reportedUsername, reportedUsername)
	reporterUsernameField := "Reporter"
	reporterUsernameValue := reporterUsername
	reasonField := "Reason"
	reasonValue := reason

	embed := discordwebhook.Embed{
		Title:       &title,
		Description: &description,
		Fields: &[]discordwebhook.Field{
			{
				Name:  &reporterUsernameField,
				Value: &reporterUsernameValue,
			},
			{
				Name:  &reasonField,
				Value: &reasonValue,
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
		log.Println("Error sending message to Discord webhook:", err)
		http.Error(w, "Failed to report user", http.StatusInternalServerError)
		return
	}

	w.Write([]byte("User reported successfully"))
}

// ReportPost handles reporting a post
func ReportPost(w http.ResponseWriter, r *http.Request) {
	reportedPostID := r.URL.Query().Get("reportedPostID")
	reporterID := r.URL.Query().Get("reporterID")
	reason := r.URL.Query().Get("reason")

	db := r.Context().Value("db").(*mongo.Client)
	reporterUsername, err := getReporterUsername(r.Context(), db, reporterID)
	if err != nil {
		log.Println("Error fetching reporter username:", err)
		http.Error(w, `{"error": "Failed to fetch reporter username"}`, http.StatusInternalServerError)
		return
	}

	if reporterUsername == "" {
		http.Error(w, `{"error": "Invalid reporter ID"}`, http.StatusBadRequest)
		return
	}

	postCollection := db.Database("SocialFlux").Collection("posts")

	// Check if the reportedPostID exists in the posts collection
	filter := bson.M{"_id": reportedPostID}
	var existingPost struct {
		ID string `bson:"_id,omitempty"`
	}

	err = postCollection.FindOne(r.Context(), filter).Decode(&existingPost)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			http.Error(w, `{"error": "Invalid reported post ID"}`, http.StatusBadRequest)
			return
		}
		log.Println("Error checking post existence:", err)
		http.Error(w, "Failed to check post existence", http.StatusInternalServerError)
		return
	}

	webhookURL := os.Getenv("Report_URL")

	title := "🚨 Post Report 🚨"
	description := fmt.Sprintf("[Reported Post](https://netsocial.app/post/%s)", reportedPostID)
	reporterUsernameField := "Reporter"
	reporterUsernameValue := reporterUsername
	reasonField := "Reason"
	reasonValue := reason

	embed := discordwebhook.Embed{
		Title:       &title,
		Description: &description,
		Fields: &[]discordwebhook.Field{
			{
				Name:  &reporterUsernameField,
				Value: &reporterUsernameValue,
			},
			{
				Name:  &reasonField,
				Value: &reasonValue,
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
		log.Println("Error sending message to Discord webhook:", err)
		http.Error(w, "Failed to report post", http.StatusInternalServerError)
		return
	}

	w.Write([]byte("Post reported successfully"))
}

// ReportCoterie handles reporting a coterie
func ReportCoterie(w http.ResponseWriter, r *http.Request) {
	CoterieName := r.URL.Query().Get("Coterie")
	reporterID := r.URL.Query().Get("reporterID")
	reason := r.URL.Query().Get("reason")

	db := r.Context().Value("db").(*mongo.Client)
	reporterUsername, err := getReporterUsername(r.Context(), db, reporterID)
	if err != nil {
		log.Println("Error fetching reporter username:", err)
		http.Error(w, `{"error": "Failed to fetch reporter username"}`, http.StatusInternalServerError)
		return
	}

	if reporterUsername == "" {
		http.Error(w, `{"error": "Invalid reporter ID"}`, http.StatusBadRequest)
		return
	}

	coterieCollection := db.Database("SocialFlux").Collection("coterie")

	// Check if the Coterie exists in the collection
	filter := bson.M{"name": CoterieName}
	var Coterie struct {
		ID   string `bson:"_id,omitempty"`
		Name string `json:"name"`
	}

	err = coterieCollection.FindOne(r.Context(), filter).Decode(&Coterie)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			http.Error(w, `{"error": "Invalid reported coterie name"}`, http.StatusBadRequest)
			return
		}
		log.Println("Error checking coterie existence:", err)
		http.Error(w, "Failed to check coterie existence", http.StatusInternalServerError)
		return
	}

	webhookURL := os.Getenv("Report_URL")

	title := "🚨 Coterie Report 🚨"
	description := fmt.Sprintf("[Reported Coterie](https://netsocial.app/coterie/%s)", Coterie.Name)
	reporterUsernameField := "Reporter"
	reporterUsernameValue := reporterUsername
	reasonField := "Reason"
	reasonValue := reason

	embed := discordwebhook.Embed{
		Title:       &title,
		Description: &description,
		Fields: &[]discordwebhook.Field{
			{
				Name:  &reporterUsernameField,
				Value: &reporterUsernameValue,
			},
			{
				Name:  &reasonField,
				Value: &reasonValue,
			},
		},
	}

	content := fmt.Sprintf("Coterie %s has been reported by %s for reason: %s", CoterieName, reporterUsername, reason)
	message := discordwebhook.Message{
		Content: &content,
		Embeds:  &[]discordwebhook.Embed{embed},
	}

	err = discordwebhook.SendMessage(webhookURL, message)
	if err != nil {
		log.Println("Error sending message to Discord webhook:", err)
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
