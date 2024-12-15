package routes

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"netsocial/middlewares"
	"netsocial/types"
)

// AddComment adds a new comment to a post
func AddComment(w http.ResponseWriter, r *http.Request) {
	db, ok := r.Context().Value("db").(*sql.DB)
	if !ok {
		http.Error(w, `{"error": "Database connection not available"}`, http.StatusInternalServerError)
		return
	}
	postID := r.Header.Get("X-id")
	content := r.Header.Get("X-content")
	encryptedauthorID := r.Header.Get("X-userID")

	if postID == "" || content == "" || encryptedauthorID == "" {
		http.Error(w, `{"error": "Missing required query parameters"}`, http.StatusBadRequest)
		return
	}

	authorID, err := middlewares.DecryptAES(encryptedauthorID)
	if err != nil {
		http.Error(w, "Failed to decrypt userid", http.StatusBadRequest)
		return
	}

	if len(authorID) != 36 {
		http.Error(w, `{"error": "Invalid author ID format"}`, http.StatusBadRequest)
		return
	}

	comment := types.NewComment{
		ID:        uuid.New().String(),
		Content:   content,
		Author:    authorID,
		CreatedAt: time.Now(),
	}

	var author types.User
	err = db.QueryRowContext(context.Background(), `SELECT id, isBanned FROM users WHERE id = $1`, authorID).Scan(&author.ID, &author.IsBanned)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, `{"error": "Author not found"}`, http.StatusBadRequest)
			return
		}
		http.Error(w, `{"error": "Failed to verify author"}`, http.StatusInternalServerError)
		return
	}

	if author.IsBanned {
		http.Error(w, `{"message": "Hey there, you are banned from using NetSocial's services."}`, http.StatusForbidden)
		return
	}

	// Serialize the comment to JSON
	commentJSON, err := json.Marshal(comment)
	if err != nil {
		return
	}

	// Retrieve the current comments for the post as raw JSON bytes
	var currentCommentsBytes []byte
	err = db.QueryRowContext(context.Background(), `SELECT comments FROM post WHERE id = $1`, postID).Scan(&currentCommentsBytes)
	if err != nil && err != sql.ErrNoRows {
		http.Error(w, `{"error": "Failed to retrieve current comments"}`, http.StatusInternalServerError)
		return
	}

	// Unmarshal the current comments bytes into a slice of json.RawMessage
	var currentComments []json.RawMessage
	if len(currentCommentsBytes) > 0 {
		err = json.Unmarshal(currentCommentsBytes, &currentComments)
		if err != nil {
			http.Error(w, `{"error": "Failed to unmarshal current comments"}`, http.StatusInternalServerError)
			return
		}
	}

	// Append the new comment to the existing comments
	currentComments = append(currentComments, commentJSON)

	// Update the post with the new comment
	updatedCommentsJSON, err := json.Marshal(currentComments)
	if err != nil {
		http.Error(w, `{"error": "Failed to serialize updated comments"}`, http.StatusInternalServerError)
		return
	}

	_, err = db.ExecContext(context.Background(), `
		UPDATE post
		SET comments = $1
		WHERE id = $2
	`, updatedCommentsJSON, postID)
	if err != nil {
		http.Error(w, `{"error": "Failed to add comment to post"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(comment); err != nil {
		http.Error(w, `{"error": "Failed to encode response"}`, http.StatusInternalServerError)
	}
}
