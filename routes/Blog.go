package routes

import (
	"context"
	"encoding/json"
	"log"
	"net/http"

	"netsocial/types"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

// GetPosts retrieves all blog posts from the database
func GetPosts(w http.ResponseWriter, r *http.Request) {
	db, ok := r.Context().Value("db").(*mongo.Client)
	if !ok {
		http.Error(w, "Database connection not available", http.StatusInternalServerError)
		return
	}

	blogCollection := db.Database("SocialFlux").Collection("blogposts")

	var blogs []types.BlogPost
	cursor, err := blogCollection.Find(context.Background(), bson.D{})
	if err != nil {
		logAndReturnError(w, "Failed to fetch blog posts", err)
		return
	}
	defer cursor.Close(context.Background())

	if err := cursor.All(context.Background(), &blogs); err != nil {
		logAndReturnError(w, "Failed to decode blog posts", err)
		return
	}

	// Set the response header to application/json
	w.Header().Set("Content-Type", "application/json")
	// Encode blogs to JSON and write to the response
	if err := json.NewEncoder(w).Encode(blogs); err != nil {
		logAndReturnError(w, "Failed to encode blog posts", err)
		return
	}
}

// logAndReturnError logs an error message and writes an error response
func logAndReturnError(w http.ResponseWriter, msg string, err error) {
	log.Println(msg+":", err)
	http.Error(w, msg, http.StatusInternalServerError)
}
