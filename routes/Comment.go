package routes

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"netsocial/types"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// AddComment adds a new comment to a post
func AddComment(w http.ResponseWriter, r *http.Request) {
	// Get the MongoDB client from the context
	db, ok := r.Context().Value("db").(*mongo.Client)
	if !ok {
		http.Error(w, `{"error": "Database connection not available"}`, http.StatusInternalServerError)
		return
	}

	// Parse query parameters
	postID := r.URL.Query().Get("id")
	content := r.URL.Query().Get("content")
	authorIDStr := r.URL.Query().Get("author")

	// Validate the inputs
	if postID == "" || content == "" || authorIDStr == "" {
		http.Error(w, `{"error": "Missing required query parameters"}`, http.StatusBadRequest)
		return
	}

	// Convert authorIDStr to ObjectID
	authorObjectID, err := primitive.ObjectIDFromHex(authorIDStr)
	if err != nil {
		http.Error(w, `{"error": "Invalid author ID"}`, http.StatusBadRequest)
		return
	}

	// Create a new comment
	comment := types.NewComment{
		ID:        primitive.NewObjectID(),
		Content:   content,
		Author:    authorObjectID,
		CreatedAt: time.Now(),
	}

	// Define collections
	postsCollection := db.Database("SocialFlux").Collection("posts")
	usersCollection := db.Database("SocialFlux").Collection("users")

	// Verify that the author exists
	var author types.User
	err = usersCollection.FindOne(context.Background(), bson.M{"_id": authorObjectID}).Decode(&author)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			http.Error(w, `{"error": "Author not found"}`, http.StatusBadRequest)
			return
		}
		log.Printf("Error finding author: %v", err)
		http.Error(w, `{"error": "Failed to verify author"}`, http.StatusInternalServerError)
		return
	}

	// Check if the author is banned
	if author.IsBanned {
		http.Error(w, `{"message": "Hey there, you are banned from using NetSocial's services."}`, http.StatusForbidden)
		return
	}

	// Update the post with the new comment
	filter := bson.M{"_id": postID} // Use postID as a string
	update := bson.M{"$push": bson.M{"comments": comment}}
	opts := options.FindOneAndUpdate().SetReturnDocument(options.After)

	var updatedPost types.Post
	err = postsCollection.FindOneAndUpdate(context.Background(), filter, update, opts).Decode(&updatedPost)
	if err != nil {
		log.Printf("Error updating post: %v", err)
		http.Error(w, `{"error": "Failed to add comment to post"}`, http.StatusInternalServerError)
		return
	}

	// Respond with the updated post
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(updatedPost)
}
