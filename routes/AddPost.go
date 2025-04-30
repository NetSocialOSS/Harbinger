package routes

import (
	"context"
	"encoding/json"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"

	"netsocial/database"
	"netsocial/middlewares"
	"netsocial/types"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/lib/pq"
)

func generateUniqueID(db *pgxpool.Pool) (string, error) {
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
		err := db.QueryRow(context.Background(), "select count(*) from post where id = $1", id).Scan(&count)
		if err != nil {
			return "", err
		}
		if count == 0 {
			return id, nil
		}
	}
}

func AddPost(w http.ResponseWriter, r *http.Request) {
	db := r.Context().Value(database.DBContextKey).(*pgxpool.Pool)
	var err error
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

	var validOptions []types.NewOptions
	if optionsStr != "" {
		options := strings.Split(optionsStr, ",")
		for _, option := range options {
			trimmedOption := strings.TrimSpace(option)
			if trimmedOption != "" {
				validOptions = append(validOptions, types.NewOptions{
					ID:   uuid.New().String(),
					Name: trimmedOption,
				})
			}
		}

		if len(validOptions) < 2 || len(validOptions) > 4 {
			http.Error(w, "Please provide between 2 and 4 poll options", http.StatusBadRequest)
			return
		}
	}

	if title == "" || content == "" || userID == "" {
		http.Error(w, "Title, content, and user ID are required", http.StatusBadRequest)
		return
	}

	var isBanned bool
	err = db.QueryRow(context.Background(), "select isbanned from users where id = $1", userID).Scan(&isBanned)
	if err != nil {
		http.Error(w, "Failed to fetch user information", http.StatusInternalServerError)
		return
	}

	if isBanned {
		http.Error(w, "You are banned from using NetSocial's services.", http.StatusForbidden)
		return
	}

	if coterieName != "" {
		var members []string
		err = db.QueryRow(context.Background(), "select members from coterie where name = $1", coterieName).Scan(pq.Array(&members))
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

	postID, err := generateUniqueID(db)
	if err != nil {
		http.Error(w, "Failed to generate unique post ID", http.StatusInternalServerError)
		return
	}

	var scheduledFor *time.Time
	if scheduledForStr != "" {
		parsedTime, err := time.Parse(time.RFC3339, scheduledForStr)
		if err != nil {
			http.Error(w, "Invalid format for scheduled time", http.StatusBadRequest)
			return
		}
		scheduledFor = &parsedTime
	}

	var pollJSON *string
	if len(validOptions) > 0 {
		poll := types.NewPoll{
			ID:        uuid.New().String(),
			Options:   validOptions,
			CreatedAt: time.Now(),
		}

		if expirationStr != "" {
			decodedExpirationStr, err := url.QueryUnescape(expirationStr)
			if err != nil {
				http.Error(w, "Failed to decode expiration time", http.StatusBadRequest)
				return
			}

			expirationTime, err := time.Parse(time.RFC3339, decodedExpirationStr)
			if err != nil {
				http.Error(w, "Invalid expiration time", http.StatusBadRequest)
				return
			}

			poll.Expiration = expirationTime
		}

		pollBytes, err := json.Marshal(poll)
		if err != nil {
			http.Error(w, "Failed to process poll options", http.StatusInternalServerError)
			return
		}

		pollStr := string(pollBytes)
		pollJSON = &pollStr
	}

	var images []string
	if image != "" {
		images = strings.Split(image, ",")
	}

	query := `
	insert into post (id, title, content, author, isindexed, coterie, scheduledfor, image, poll, hearts)
	values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	returning createdat
`
	var createdAt time.Time
	err = db.QueryRow(context.Background(), query,
		postID,
		title,
		content,
		userID,
		indexing,
		coterieName,
		scheduledFor,
		pq.Array(images),
		pollJSON,
		pq.Array([]string{}),
	).Scan(&createdAt)

	if err != nil {
		http.Error(w, "Failed to create post", http.StatusInternalServerError)
		log.Println(err)
		return
	}

	// Build debug response
	postData := map[string]interface{}{
		"id":           postID,
		"title":        title,
		"content":      content,
		"author":       userID,
		"isIndexed":    indexing,
		"coterie":      coterieName,
		"scheduledFor": scheduledFor,
		"images":       images,
		"poll":         pollJSON,
		"hearts":       []string{},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(postData); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}
