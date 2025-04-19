package routes

import (
	"context"
	"encoding/json"
	"net/http"
	"netsocial/database"
	"netsocial/middlewares"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v4/pgxpool"
)

// DeletePost handles the deletion of a post
func DeletePost(w http.ResponseWriter, r *http.Request) {
	db, ok := r.Context().Value(database.DBContextKey).(*pgxpool.Pool)
	if !ok {
		http.Error(w, `{"error": "Database connection not available"}`, http.StatusInternalServerError)
		return
	}

	postID := r.Header.Get("X-postid")

	encrypteduserId := r.Header.Get("X-userID")
	if encrypteduserId == "" {
		http.Error(w, "userId query parameter is required", http.StatusBadRequest)
		return
	}

	authorID, err := middlewares.DecryptAES(encrypteduserId)
	if err != nil {
		http.Error(w, "Failed to decrypt userid", http.StatusBadRequest)
		return
	}

	authorUUID, err := uuid.Parse(authorID)
	if err != nil {
		http.Error(w, "Invalid author ID", http.StatusBadRequest)
		return
	}

	if postID == "" || authorUUID == uuid.Nil {
		http.Error(w, `{"error": "Post ID or Author ID is missing"}`, http.StatusBadRequest)
		return
	}

	query := `DELETE FROM Post WHERE id = $1 AND author = $2`

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	result, err := db.Exec(ctx, query, postID, authorID)
	if err != nil {
		http.Error(w, `{"error": "Failed to delete post"}`, http.StatusInternalServerError)
		return
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		http.Error(w, `{"error": "Post not found or you are not the author"}`, http.StatusNotFound)
		return
	}

	response := map[string]string{
		"message": "Post deleted successfully",
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, `{"error": "Failed to encode response"}`, http.StatusInternalServerError)
	}
}
