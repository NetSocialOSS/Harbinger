package routes

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"

	"netsocial/database"
	"netsocial/middlewares"
	"netsocial/types"
)

func AddComment(w http.ResponseWriter, r *http.Request) {
	db, ok := r.Context().Value(database.DBContextKey).(*pgxpool.Pool)
	if !ok {
		http.Error(w, `{"error": "Database connection not available"}`, http.StatusInternalServerError)
		return
	}
	postID := r.Header.Get("X-id")
	content := r.Header.Get("X-content")

	if postID == "" || content == "" {
		http.Error(w, `{"error": "Missing required query parameters"}`, http.StatusBadRequest)
		return
	}

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

	comment := types.NewComment{
		ID:        uuid.New().String(),
		Content:   content,
		Author:    authorID,
		CreatedAt: time.Now(),
	}

	var author types.User
	err = db.QueryRow(context.Background(), `SELECT id, isBanned FROM users WHERE id = $1`, authorID).Scan(&author.ID, &author.IsBanned)
	if err != nil {
		if err == pgx.ErrNoRows {
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
	err = db.QueryRow(context.Background(), `SELECT comments FROM post WHERE id = $1`, postID).Scan(&currentCommentsBytes)
	if err != nil && err != pgx.ErrNoRows {
		http.Error(w, `{"error": "Failed to retrieve current comments"}`, http.StatusInternalServerError)
		println(err.Error())
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
	currentComments = append(currentComments, json.RawMessage(commentJSON))

	// Update the post with the new comment
	updatedCommentsJSON, err := json.Marshal(currentComments)
	if err != nil {
		http.Error(w, `{"error": "Failed to serialize updated comments"}`, http.StatusInternalServerError)
		return
	}

	_, err = db.Exec(context.Background(), `
	UPDATE post
	SET comments = $1
	WHERE id = $2
`, updatedCommentsJSON, postID)
	if err != nil {
		http.Error(w, `{"error": "Failed to add comment to post"}`, http.StatusInternalServerError)
		return
	}

	var commenterDisplayName, authorId string
	if err = db.QueryRow(r.Context(), "SELECT displayname FROM users WHERE id = $1", authorID).Scan(&commenterDisplayName); err != nil {
		http.Error(w, "Error fetching display name", http.StatusInternalServerError)
		return
	}
	if err = db.QueryRow(r.Context(), "SELECT author FROM post WHERE id = $1", postID).Scan(&authorId); err != nil {
		http.Error(w, "Error fetching post author", http.StatusInternalServerError)
		return
	}

	// Skip notification if the user is liking their own post
	if authorID != authorId {
		_, err = db.Exec(r.Context(),
			"INSERT INTO notifications (userid, type, content, link) VALUES ($1, $2, $3, $4)",
			authorId, "like", fmt.Sprintf("you've recieved a comment on your post by %s !", commenterDisplayName), fmt.Sprintf("/post/%s", postID))
		if err != nil {
			http.Error(w, "Error creating like notification", http.StatusInternalServerError)
			println(err)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(comment); err != nil {
		http.Error(w, `{"error": "Failed to encode response"}`, http.StatusInternalServerError)
	}
}
