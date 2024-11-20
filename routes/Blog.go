package routes

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"netsocial/middlewares"
	"netsocial/types"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

func GetPosts(w http.ResponseWriter, r *http.Request) {
	db, ok := r.Context().Value("db").(*mongo.Client)
	if !ok {
		http.Error(w, "Database connection not available", http.StatusInternalServerError)
		return
	}

	blogCollection := db.Database("SocialFlux").Collection("blogposts")
	userCollection := db.Database("SocialFlux").Collection("users")

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

	var responsePosts []map[string]interface{}

	for _, blog := range blogs {
		var user types.User
		err := userCollection.FindOne(context.Background(), bson.M{"id": blog.AuthorID}).Decode(&user)
		if err == mongo.ErrNoDocuments {
			log.Println("Warning: Author not found for blog post ID:", blog.ID)
			continue
		} else if err != nil {
			logAndReturnError(w, "Failed to fetch author details", err)
			return
		}

		postMap := map[string]interface{}{
			"id":           blog.ID,
			"slug":         blog.Slug,
			"title":        blog.Title,
			"date":         blog.Date,
			"authorname":   user.DisplayName,
			"authoravatar": user.ProfilePicture,
			"overview":     blog.Overview,
			"content":      blog.Content,
		}

		responsePosts = append(responsePosts, postMap)
	}

	// Set the response header to application/json
	w.Header().Set("Content-Type", "application/json")
	// Encode responsePosts to JSON and write to the response
	if err := json.NewEncoder(w).Encode(responsePosts); err != nil {
		logAndReturnError(w, "Failed to encode blog posts", err)
		return
	}
}

// logAndReturnError logs an error message and writes an error response
func logAndReturnError(w http.ResponseWriter, msg string, err error) {
	log.Println(msg+":", err)
	http.Error(w, msg, http.StatusInternalServerError)
}

func AddBlogPost(w http.ResponseWriter, r *http.Request) {
	db, ok := r.Context().Value("db").(*mongo.Client)
	if !ok {
		http.Error(w, "Database connection not available", http.StatusInternalServerError)
		return
	}

	encryptedid := r.Header.Get("X-userId")
	Title := r.URL.Query().Get("title")
	Overview := r.URL.Query().Get("overview")

	UserID, err := middlewares.DecryptAES(encryptedid)
	if err != nil {
		http.Error(w, "Failed to decrypt userid", http.StatusBadRequest)
		return
	}

	var Content []types.PostEntry
	contentStr := r.URL.Query().Get("content")
	if err := json.Unmarshal([]byte(contentStr), &Content); err != nil {
		http.Error(w, "Invalid content format", http.StatusBadRequest)
		return
	}

	// Since UserID is now a UUID string, we don't need ObjectIDFromHex
	_, err = uuid.Parse(UserID)
	if err != nil {
		http.Error(w, "Invalid user ID format", http.StatusBadRequest)
		return
	}

	userCollection := db.Database("SocialFlux").Collection("users")
	var user types.User

	// Query the users collection using UUID string
	err = userCollection.FindOne(context.Background(), bson.M{"id": UserID}).Decode(&user)
	if err == mongo.ErrNoDocuments || !(user.IsDeveloper || user.IsOwner) {
		http.Error(w, "User not authorized to add posts", http.StatusForbidden)
		return
	} else if err != nil {
		logAndReturnError(w, "Failed to fetch user data", err)
		return
	}

	blogCollection := db.Database("SocialFlux").Collection("blogposts")
	newPost := types.BlogPost{
		ID:       uuid.New().String(),
		Slug:     generateSlug(Title),
		Title:    Title,
		Date:     time.Now().Format("January 02, 2006"),
		AuthorID: UserID,
		Overview: Overview,
		Content:  Content,
	}

	_, err = blogCollection.InsertOne(context.Background(), newPost)
	if err != nil {
		logAndReturnError(w, "Failed to insert blog post", err)
		return
	}

	// Respond with success
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(newPost); err != nil {
		logAndReturnError(w, "Failed to encode response", err)
		return
	}
}

// Helper function to generate a slug from the title
func generateSlug(title string) string {
	return strings.ToLower(strings.ReplaceAll(title, " ", "-"))
}

func Blogs(r chi.Router) {
	r.Get("/blog/posts/@all", GetPosts)
	r.Post("/blog/new", AddBlogPost)
}
