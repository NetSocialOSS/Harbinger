package routes

import (
	"context"
	"encoding/json"
	"net/http"
	"netsocial/middlewares"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

// DeletePost handles the deletion of a post by its ID and author's UUID
func DeletePost(w http.ResponseWriter, r *http.Request) {
	// Get the database connection from the context
	db, ok := r.Context().Value("db").(*mongo.Client)
	if !ok {
		http.Error(w, `{"error": "Database connection not available"}`, http.StatusInternalServerError)
		return
	}

	// Get the posts collection
	postsCollection := db.Database("SocialFlux").Collection("posts")

	// Extract post ID and author ID from headers
	postID := r.Header.Get("X-postid")
	encryptedauthorID := r.Header.Get("X-userID")

	authorID, err := middlewares.DecryptAES(encryptedauthorID)
	if err != nil {
		http.Error(w, "Failed to decrypt userid", http.StatusBadRequest)
		return
	}

	// Validate that the IDs are not empty
	if postID == "" || encryptedauthorID == "" {
		http.Error(w, `{"error": "Post ID or Author ID is missing"}`, http.StatusBadRequest)
		return
	}

	// Create a filter for deleting the post
	filter := bson.M{
		"_id":    postID,
		"author": authorID, // No conversion needed for UUID
	}

	// Set a context with a timeout for the delete operation
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Perform the delete operation
	result, err := postsCollection.DeleteOne(ctx, filter)
	if err != nil {
		http.Error(w, `{"error": "Failed to delete post"}`, http.StatusInternalServerError)
		return
	}

	// Check if a post was deleted
	if result.DeletedCount == 0 {
		http.Error(w, `{"error": "Post not found or you are not the author"}`, http.StatusNotFound)
		return
	}

	// Construct response
	response := map[string]string{
		"message": "Post deleted successfully",
	}

	// Send JSON response
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, `{"error": "Failed to encode response"}`, http.StatusInternalServerError)
	}
}
