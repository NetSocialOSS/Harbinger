package routes

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"netsocial/middlewares"
	"netsocial/types"

	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

func generateUniqueID(collection *mongo.Collection) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	seededRand := rand.New(rand.NewSource(time.Now().UnixNano()))

	for {
		b := make([]byte, 8)
		for i := range b {
			b[i] = charset[seededRand.Intn(len(charset))]
		}
		id := string(b)

		// Check if the ID already exists
		count, err := collection.CountDocuments(context.Background(), bson.M{"_id": id})
		if err != nil {
			return "", err
		}
		if count == 0 {
			return id, nil
		}
	}
}

func AddPost(w http.ResponseWriter, r *http.Request) {
	db := r.Context().Value("db").(*mongo.Client)
	if db == nil {
		http.Error(w, "Database connection not available", http.StatusInternalServerError)
		return
	}

	postsCollection := db.Database("SocialFlux").Collection("posts")
	usersCollection := db.Database("SocialFlux").Collection("users")
	coteriesCollection := db.Database("SocialFlux").Collection("coterie")

	title := r.Header.Get("X-title")
	content := r.Header.Get("X-content")
	encrypteduserId := r.Header.Get("X-userID")
	image := r.Header.Get("X-image")
	coterieName := r.Header.Get("X-coterie")
	scheduledForStr := r.Header.Get("X-scheduledFor")
	optionsStr := r.Header.Get("X-options")
	expirationStr := r.Header.Get("X-expiration")
	indexingStr := r.Header.Get("X-indexing")
	indexing := false

	if indexingStr != "" {
		// Validate the X-indexing header, must be "true" or "false"
		if indexingStr == "true" {
			indexing = true
		} else if indexingStr != "true" {
			http.Error(w, "Invalid value for X-indexing. It must be 'true' or 'false'", http.StatusBadRequest)
			return
		}
	}
	userId, err := middlewares.DecryptAES(encrypteduserId)
	if err != nil {
		http.Error(w, "Failed to decrypt userid", http.StatusBadRequest)
		return
	}

	// Split options by comma only if optionsStr is provided
	var validOptions []string
	if optionsStr != "" {
		options := strings.Split(optionsStr, ",")
		// Trim whitespace from each option
		for _, option := range options {
			trimmedOption := strings.TrimSpace(option)
			if trimmedOption != "" {
				validOptions = append(validOptions, trimmedOption)
			}
		}

		// Validate that we have at least 2 and no more than 4 options if provided
		if len(validOptions) < 2 || len(validOptions) > 4 {
			http.Error(w, "Please provide between 2 and 4 poll options", http.StatusBadRequest)
			return
		}
	}

	// Remaining validation...
	if title == "" || content == "" || userId == "" {
		http.Error(w, "Title, content, and user ID are required", http.StatusBadRequest)
		return
	}

	// Validate the userId as a UUID
	_, err = uuid.Parse(userId)
	if err != nil {
		http.Error(w, "Invalid user ID.", http.StatusBadRequest)
		return
	}

	// Check if the user exists and if they are banned
	var user types.User
	err = usersCollection.FindOne(r.Context(), bson.M{"id": userId}).Decode(&user)
	if err != nil {
		http.Error(w, "Failed to fetch user information", http.StatusInternalServerError)
		return
	}

	if user.IsBanned {
		http.Error(w, "You are banned from using NetSocial's services.", http.StatusForbidden)
		return
	}

	// Validate coterie membership
	if coterieName != "" {
		var coterie types.Coterie
		err = coteriesCollection.FindOne(r.Context(), bson.M{"name": coterieName}).Decode(&coterie)
		if err != nil {
			http.Error(w, "Failed to fetch coterie information", http.StatusInternalServerError)
			return
		}

		isMember := false
		for _, memberID := range coterie.Members {
			if memberID == userId {
				isMember = true
				break
			}
		}

		if !isMember {
			http.Error(w, "User is not a member of the coterie", http.StatusForbidden)
			return
		}
	}

	// Generate a unique post ID
	postID, err := generateUniqueID(postsCollection)
	if err != nil {
		http.Error(w, "Failed to generate unique post ID", http.StatusInternalServerError)
		return
	}

	// Parse ScheduledFor time
	var scheduledFor time.Time
	if scheduledForStr != "" {
		scheduledFor, err = time.Parse(time.RFC3339, scheduledForStr)
		if err != nil {
			http.Error(w, "Invalid format for scheduled time", http.StatusBadRequest)
			return
		}
	}

	// Process poll options only if valid options exist
	var poll bson.M
	if len(validOptions) > 0 {
		var pollOptions []bson.M
		for _, option := range validOptions {
			optionID := primitive.NewObjectID()
			pollOptions = append(pollOptions, bson.M{
				"_id":   optionID,
				"name":  option,
				"votes": []string{},
			})
		}
		optionID := primitive.NewObjectID()
		// Construct the poll object
		poll = bson.M{

			"_id":        optionID,
			"options":    pollOptions,
			"createdAt":  time.Now(),
			"expiration": time.Time{}, // Default to zero value if not specified
		}

		// Only parse expiration if it is provided
		if expirationStr != "" {
			expirationTime, err := time.Parse(time.RFC3339, expirationStr)
			if err != nil {
				http.Error(w, fmt.Sprintf("Invalid expiration date format. Use RFC3339 format. Received: %s", expirationStr), http.StatusBadRequest)
				return
			}
			poll["expiration"] = expirationTime // Set the parsed expiration time
		}
	}

	// Create the post document
	post := bson.M{
		"_id":       postID,
		"title":     title,
		"content":   content,
		"author":    userId,
		"hearts":    []string{},
		"isIndexed": indexing,
		"createdAt": time.Now(),
	}

	if coterieName != "" {
		post["coterie"] = coterieName
	}

	if !scheduledFor.IsZero() {
		post["scheduledFor"] = scheduledFor
	}

	// Add the Image field only if image URLs are provided
	if image != "" {
		imageArray := strings.FieldsFunc(image, func(r rune) bool {
			return r == ','
		})
		post["image"] = imageArray
	}

	// Include the poll in the post if it exists
	if poll != nil {
		post["poll"] = []bson.M{poll}
	}

	_, err = postsCollection.InsertOne(r.Context(), post)
	if err != nil {
		http.Error(w, "Failed to create post", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	fmt.Fprint(w, `{"message": "Post successfully created!", "postId": "`+postID+`"}`)
}
