package routes

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"netsocial/middlewares"
	"time"

	_ "github.com/lib/pq"
)

// DeletePost handles the deletion of a post
func DeletePost(w http.ResponseWriter, r *http.Request) {
	db, ok := r.Context().Value("db").(*sql.DB)
	if !ok {
		http.Error(w, `{"error": "Database connection not available"}`, http.StatusInternalServerError)
		return
	}

	postID := r.Header.Get("X-postid")
	encryptedAuthorID := r.Header.Get("X-userID")

	authorID, err := middlewares.DecryptAES(encryptedAuthorID)
	if err != nil {
		http.Error(w, "Failed to decrypt userid", http.StatusBadRequest)
		return
	}

	if postID == "" || encryptedAuthorID == "" {
		http.Error(w, `{"error": "Post ID or Author ID is missing"}`, http.StatusBadRequest)
		return
	}

	query := `DELETE FROM Post WHERE id = $1 AND author = $2`

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	result, err := db.ExecContext(ctx, query, postID, authorID)
	if err != nil {
		http.Error(w, `{"error": "Failed to delete post"}`, http.StatusInternalServerError)
		return
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		http.Error(w, `{"error": "Failed to determine deletion status"}`, http.StatusInternalServerError)
		return
	}

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
