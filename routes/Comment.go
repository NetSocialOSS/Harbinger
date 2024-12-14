package routes

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
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

	// Verify that the author exists
	var author types.User
	err = db.QueryRowContext(context.Background(), `SELECT id, isBanned FROM users WHERE id = $1`, authorID).Scan(&author.ID, &author.IsBanned)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, `{"error": "Author not found"}`, http.StatusBadRequest)
			return
		}
		log.Printf("Error finding author: %v", err)
		http.Error(w, `{"error": "Failed to verify author"}`, http.StatusInternalServerError)
		return
	}

	if author.IsBanned {
		http.Error(w, `{"message": "Hey there, you are banned from using NetSocial's services."}`, http.StatusForbidden)
		return
	}

	_, err = db.ExecContext(context.Background(), `
		UPDATE "Post"
		SET comments = array_append(comments, $1)
		WHERE id = $2
	`, comment, postID)
	if err != nil {
		log.Printf("Error updating post: %v", err)
		http.Error(w, `{"error": "Failed to add comment to post"}`, http.StatusInternalServerError)
		return
	}

	// Respond with the updated post (For now, just return the new comment)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(comment)
}
