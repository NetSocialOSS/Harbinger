package routes

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"netsocial/database"
	"netsocial/middlewares"
	"netsocial/types"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v4/pgxpool"
)

var (
	blog        types.BlogPost
	user        types.User
	postEntries []types.PostEntry
)

func GetPosts(w http.ResponseWriter, r *http.Request) {
	db, ok := r.Context().Value(database.DBContextKey).(*pgxpool.Pool)
	if !ok {
		http.Error(w, "Database connection not available", http.StatusInternalServerError)
		return
	}

	// Query to get all blog posts
	rows, err := db.Query(context.Background(), "SELECT id, slug, title, date, authorId, overview, content FROM blogpost")
	if err != nil {
		logAndReturnError(w, "Failed to fetch blog posts", err)
		return
	}
	defer rows.Close()

	var responsePosts []map[string]interface{}

	for rows.Next() {
		var authorId string
		var content []string
		err := rows.Scan(&blog.ID, &blog.Slug, &blog.Title, &blog.Date, &authorId, &blog.Overview, &content)
		if err != nil {
			logAndReturnError(w, "Failed to decode blog post", err)
			return
		}

		// Convert []string (content) to []PostEntry
		for _, body := range content {
			postEntries = append(postEntries, types.PostEntry{Body: body})
		}
		blog.Content = postEntries

		// Fetch author details
		err = db.QueryRow(context.Background(), `SELECT username, displayName, profilePicture FROM users WHERE id = $1`, authorId).Scan(&user.Username, &user.DisplayName, &user.ProfilePicture)

		if err != nil {
			continue
		}

		postMap := map[string]interface{}{
			"id":           blog.ID,
			"slug":         blog.Slug,
			"title":        blog.Title,
			"date":         blog.Date,
			"authorname":   user.DisplayName,
			"authoravatar": user.ProfilePicture,
			"overview":     blog.Overview,
			"content":      blog.Content,
		}

		responsePosts = append(responsePosts, postMap)
	}

	// Set the response header to application/json
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(responsePosts); err != nil {
		logAndReturnError(w, "Failed to encode blog posts", err)
		return
	}
}

// logAndReturnError logs an error message and writes an error response
func logAndReturnError(w http.ResponseWriter, msg string, _ error) {
	http.Error(w, msg, http.StatusInternalServerError)
}

func AddBlogPost(w http.ResponseWriter, r *http.Request) {
	db, ok := r.Context().Value(database.DBContextKey).(*pgxpool.Pool)
	if !ok {
		http.Error(w, "Database connection not available", http.StatusInternalServerError)
		return
	}

	Title := r.URL.Query().Get("title")
	Overview := r.URL.Query().Get("overview")

	encrypteduserId := r.Header.Get("X-userID")
	if encrypteduserId == "" {
		http.Error(w, "userId query parameter is required", http.StatusBadRequest)
		return
	}

	UserID, err := middlewares.DecryptAES(encrypteduserId)
	if err != nil {
		http.Error(w, "Failed to decrypt userid", http.StatusBadRequest)
		return
	}
	// Parse the content string into a slice of PostEntry
	contentStr := r.URL.Query().Get("content")
	if err := json.Unmarshal([]byte(contentStr), &postEntries); err != nil {
		http.Error(w, "Invalid content format", http.StatusBadRequest)
		return
	}

	// Query the users table to check authorization
	err = db.QueryRow(context.Background(), "select id, isdeveloper, isowner from users where id = $1", UserID).Scan(&user.ID, &user.IsDeveloper, &user.IsOwner)
	if err != nil || !(user.IsDeveloper || user.IsOwner) {
		http.Error(w, "User not authorized to add posts", http.StatusForbidden)
		return
	}

	// Transform Content into a slice of strings
	var contentBodies []string
	for _, entry := range postEntries {
		contentBodies = append(contentBodies, entry.Body)
	}

	// Insert new blog post
	blogSlug := generateSlug(Title)
	_, err = db.Exec(context.Background(), `
		insert into blogpost (slug, title, date, authorid, overview, content) 
		values ($1, $2, $3, $4, $5, $6)`,
		blogSlug, Title, time.Now(), UserID, Overview, contentBodies,
	)
	if err != nil {
		http.Error(w, "Failed to insert blog post", http.StatusInternalServerError)
		return
	}

	// Respond with success
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "New blog post added successfully"})
}

// Helper function to generate a slug from the title
func generateSlug(title string) string {
	return strings.ToLower(strings.ReplaceAll(title, " ", "-"))
}

func Blogs(r chi.Router) {
	r.Get("/blog/posts/@all", GetPosts)
	r.Post("/blog/new", AddBlogPost)
}
