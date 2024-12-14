package routes

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"netsocial/middlewares"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

func generateUniqueID(db *sql.DB) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	seededRand := rand.New(rand.NewSource(time.Now().UnixNano()))

	for {
		b := make([]byte, 8)
		for i := range b {
			b[i] = charset[seededRand.Intn(len(charset))]
		}
		id := string(b)

		// Check if the ID already exists in PostgreSQL
		var count int
		err := db.QueryRow("SELECT COUNT(*) FROM post WHERE id = $1", id).Scan(&count)
		if err != nil {
			return "", err
		}
		if count == 0 {
			return id, nil
		}
	}
}

func AddPost(w http.ResponseWriter, r *http.Request) {
	db := r.Context().Value("db").(*sql.DB)
	if db == nil {
		http.Error(w, "Database connection not available", http.StatusInternalServerError)
		return
	}

	title := r.URL.Query().Get("title")
	content := r.URL.Query().Get("content")
	encryptedUserID := r.Header.Get("X-userID")
	image := r.Header.Get("X-image")
	coterieName := r.Header.Get("X-coterie")
	scheduledForStr := r.Header.Get("X-scheduledFor")
	optionsStr := r.Header.Get("X-options")
	expirationStr := r.Header.Get("X-expiration")
	indexingStr := r.Header.Get("X-indexing")
	indexing := false

	if indexingStr != "" {
		if indexingStr == "true" {
			indexing = true
		} else if indexingStr == "false" {
			indexing = false
		} else {
			http.Error(w, "Invalid value for X-indexing. It must be 'true' or 'false'", http.StatusBadRequest)
			return
		}
	}

	userID, err := middlewares.DecryptAES(encryptedUserID)
	if err != nil {
		http.Error(w, "Failed to decrypt user ID", http.StatusBadRequest)
		return
	}

	// Split options by comma only if optionsStr is provided
	var validOptions []string
	if optionsStr != "" {
		options := strings.Split(optionsStr, ",")
		// Trim whitespace from each option
		for _, option := range options {
			trimmedOption := strings.TrimSpace(option)
			if trimmedOption != "" {
				validOptions = append(validOptions, trimmedOption)
			}
		}

		// Validate that we have at least 2 and no more than 4 options if provided
		if len(validOptions) < 2 || len(validOptions) > 4 {
			http.Error(w, "Please provide between 2 and 4 poll options", http.StatusBadRequest)
			return
		}
	}

	if title == "" || content == "" || userID == "" {
		http.Error(w, "Title, content, and user ID are required", http.StatusBadRequest)
		return
	}

	// Validate the user ID as a UUID
	_, err = uuid.Parse(userID)
	if err != nil {
		http.Error(w, "Invalid user ID.", http.StatusBadRequest)
		return
	}

	// Check if the user exists and is not banned
	var isBanned bool
	err = db.QueryRow("SELECT isBanned FROM users WHERE id = $1", userID).Scan(&isBanned)
	if err != nil {
		http.Error(w, "Failed to fetch user information", http.StatusInternalServerError)
		return
	}

	if isBanned {
		http.Error(w, "You are banned from using NetSocial's services.", http.StatusForbidden)
		return
	}

	// Validate coterie membership
	if coterieName != "" {
		var members []string
		err = db.QueryRow("SELECT members FROM coterie WHERE name = $1", coterieName).Scan(&members)
		if err != nil {
			http.Error(w, "Failed to fetch coterie information", http.StatusInternalServerError)
			return
		}

		isMember := false
		for _, memberID := range members {
			if memberID == userID {
				isMember = true
				break
			}
		}

		if !isMember {
			http.Error(w, "User is not a member of the coterie", http.StatusForbidden)
			return
		}
	}

	// Generate a unique post ID
	postID, err := generateUniqueID(db)
	if err != nil {
		http.Error(w, "Failed to generate unique post ID", http.StatusInternalServerError)
		return
	}

	// Parse ScheduledFor time
	var scheduledFor time.Time
	if scheduledForStr != "" {
		scheduledFor, err = time.Parse(time.RFC3339, scheduledForStr)
		if err != nil {
			http.Error(w, "Invalid format for scheduled time", http.StatusBadRequest)
			return
		}
	}

	// Process poll options only if valid options exist
	var pollJSON []byte
	if optionsStr != "" {
		options := strings.Split(optionsStr, ",")
		validOptions := []map[string]interface{}{}

		for _, option := range options {
			trimmedOption := strings.TrimSpace(option)
			if trimmedOption != "" {
				validOptions = append(validOptions, map[string]interface{}{
					"id":    uuid.New().String(),
					"name":  trimmedOption,
					"votes": []string{},
				})
			}
		}

		if len(validOptions) < 2 || len(validOptions) > 4 {
			http.Error(w, "Please provide between 2 and 4 poll options", http.StatusBadRequest)
			return
		}

		poll := map[string]interface{}{
			"id":        uuid.New().String(),
			"options":   validOptions,
			"createdAt": time.Now(),
			"expiration": func() time.Time {
				if expirationStr != "" {
					expirationTime, err := time.Parse(time.RFC3339, expirationStr)
					if err == nil {
						return expirationTime
					}
				}
				return time.Time{}
			}(),
		}

		pollJSON, err = json.Marshal(poll)
		if err != nil {
			http.Error(w, "Failed to process poll options", http.StatusInternalServerError)
			return
		}
	}

	// Add the Image field only if image URLs are provided
	var images []string
	if image != "" {
		images = strings.Split(image, ",")
	}

	// Insert the post into PostgreSQL
	query := `
		INSERT INTO post (id, title, content, author, isIndexed, createdAt, coterie, scheduledFor, image, poll)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`
	_, err = db.Exec(query, postID, title, content, userID, indexing, time.Now(), coterieName, scheduledFor, pq.Array(images), string(pollJSON))
	if err != nil {
		http.Error(w, "Failed to create post", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, `{"message": "Post successfully created!", "postId": "%s"}`, postID)
}
