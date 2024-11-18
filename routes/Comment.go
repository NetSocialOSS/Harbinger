package routes

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"netsocial/middlewares"
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
	postID := r.Header.Get("X-id")
	content := r.Header.Get("X-content")
	encryptedauthorID := r.Header.Get("X-userID")

	// Validate the inputs
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

	// Create a new comment
	comment := types.NewComment{
		ID:        primitive.NewObjectID(),
		Content:   content,
		Author:    authorID,
		CreatedAt: time.Now(),
	}

	// Define collections
	postsCollection := db.Database("SocialFlux").Collection("posts")
	usersCollection := db.Database("SocialFlux").Collection("users")

	// Verify that the author exists
	var author types.User
	err = usersCollection.FindOne(context.Background(), bson.M{"id": authorID}).Decode(&author)
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

	filter := bson.M{"_id": postID}
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
