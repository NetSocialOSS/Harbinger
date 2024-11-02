package routes

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

// DeletePost handles the deletion of a post by its ID and author's primitive object ID
func DeletePost(w http.ResponseWriter, r *http.Request) {
	// Get the database connection from the context
	db, ok := r.Context().Value("db").(*mongo.Client)
	if !ok {
		http.Error(w, `{"error": "Database connection not available"}`, http.StatusInternalServerError)
		return
	}

	// Get the posts collection
	postsCollection := db.Database("SocialFlux").Collection("posts")

	// Extract post ID and author ID from query parameters
	postID := r.URL.Query().Get("postid")
	authorID := r.URL.Query().Get("authorid")

	// Convert the author ID to a primitive.ObjectID
	authorObjectID, err := primitive.ObjectIDFromHex(authorID)
	if err != nil {
		http.Error(w, `{"error": "Invalid author ID format"}`, http.StatusBadRequest)
		return
	}

	// Create a filter for deleting the post
	filter := bson.M{
		"_id":    postID,
		"author": authorObjectID,
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
