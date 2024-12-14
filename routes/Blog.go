package routes

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"netsocial/middlewares"
	"netsocial/types"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/lib/pq"
)

func GetPosts(w http.ResponseWriter, r *http.Request) {
	db, ok := r.Context().Value("db").(*sql.DB)
	if !ok {
		http.Error(w, "Database connection not available", http.StatusInternalServerError)
		return
	}

	// Query to get all blog posts
	rows, err := db.Query("SELECT id, slug, title, date, authorId, overview, content FROM blogpost")
	if err != nil {
		logAndReturnError(w, "Failed to fetch blog posts", err)
		return
	}
	defer rows.Close()

	var responsePosts []map[string]interface{}

	for rows.Next() {
		var blog types.BlogPost
		var authorId string
		var content []string
		err := rows.Scan(&blog.ID, &blog.Slug, &blog.Title, &blog.Date, &authorId, &blog.Overview, pq.Array(&content))
		if err != nil {
			logAndReturnError(w, "Failed to decode blog post", err)
			return
		}

		// Convert []string (content) to []PostEntry
		var postEntries []types.PostEntry
		for _, body := range content {
			postEntries = append(postEntries, types.PostEntry{Body: body})
		}
		blog.Content = postEntries

		// Fetch author details
		var user types.User
		err = db.QueryRow(`SELECT username, displayName, profilePicture FROM users WHERE id = $1`, authorId).Scan(&user.Username, &user.DisplayName, &user.ProfilePicture)

		if err != nil {
			log.Println("Warning: Author not found for blog post ID:", blog.ID)
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
func logAndReturnError(w http.ResponseWriter, msg string, err error) {
	log.Println(msg+":", err)
	http.Error(w, msg, http.StatusInternalServerError)
}

func AddBlogPost(w http.ResponseWriter, r *http.Request) {
	db, ok := r.Context().Value("db").(*sql.DB)
	if !ok {
		http.Error(w, "Database connection not available", http.StatusInternalServerError)
		return
	}

	encryptedid := r.Header.Get("X-userId")
	Title := r.URL.Query().Get("title")
	Overview := r.URL.Query().Get("overview")

	UserID, err := middlewares.DecryptAES(encryptedid)
	if err != nil {
		http.Error(w, "Failed to decrypt userid", http.StatusBadRequest)
		return
	}

	var Content []types.PostEntry
	contentStr := r.URL.Query().Get("content")
	if err := json.Unmarshal([]byte(contentStr), &Content); err != nil {
		http.Error(w, "Invalid content format", http.StatusBadRequest)
		return
	}

	// Since UserID is now a UUID string, we don't need ObjectIDFromHex
	_, err = uuid.Parse(UserID)
	if err != nil {
		http.Error(w, "Invalid user ID format", http.StatusBadRequest)
		return
	}

	// Query the users table to check authorization
	var user types.User
	err = db.QueryRow("SELECT id, isDeveloper, isOwner FROM users WHERE id = $1", UserID).Scan(&user.ID, &user.IsDeveloper, &user.IsOwner)
	if err != nil || !(user.IsDeveloper || user.IsOwner) {
		http.Error(w, "User not authorized to add posts", http.StatusForbidden)
		return
	}

	// Insert new blog post
	blogID := uuid.New().String()
	blogSlug := generateSlug(Title)
	_, err = db.Exec(`
		INSERT INTO blogpost (id, slug, title, date, authorId, overview, content) 
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		blogID, blogSlug, Title, time.Now(), UserID, Overview, pq.Array(Content),
	)
	if err != nil {
		logAndReturnError(w, "Failed to insert blog post", err)
		return
	}

	// Respond with success
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(map[string]string{"id": blogID}); err != nil {
		logAndReturnError(w, "Failed to encode response", err)
		return
	}
}

// Helper function to generate a slug from the title
func generateSlug(title string) string {
	return strings.ToLower(strings.ReplaceAll(title, " ", "-"))
}

func Blogs(r chi.Router) {
	r.Get("/blog/posts/@all", GetPosts)
	r.Post("/blog/new", AddBlogPost)
}
