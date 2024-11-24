package routes

import (
	"context"
	"encoding/json"
	"net/http"
	"netsocial/middlewares"
	"netsocial/types"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// CheckCoterieChatAllowed checks if chat is allowed in the specified coterie.
func CheckCoterieChatAllowed(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		db, ok := r.Context().Value("db").(*mongo.Client)
		if !ok {
			http.Error(w, `{"error": "Database connection not available"}`, http.StatusInternalServerError)
			return
		}

		// Extract the coterie name from the query parameters
		coterieName := r.URL.Query().Get("coterieName")
		if coterieName == "" {
			http.Error(w, `{"error": "Missing required field: coterieName"}`, http.StatusBadRequest)
			return
		}

		coterieCollection := db.Database("SocialFlux").Collection("coterie")

		// Find the coterie to check if chat is allowed
		var coterie types.Coterie
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		err := coterieCollection.FindOne(ctx, bson.M{"name": coterieName}).Decode(&coterie)
		if err != nil {
			if err == mongo.ErrNoDocuments {
				http.Error(w, `{"error": "Coterie not found"}`, http.StatusNotFound)
				return
			}
			http.Error(w, `{"error": "Error finding coterie: `+err.Error()+`"}`, http.StatusInternalServerError)
			return
		}

		// Check if chat is allowed for this coterie
		if !coterie.IsChatAllowed {
			http.Error(w, `{"error": "Chatting is disabled for this coterie."}`, http.StatusForbidden)
			return
		}

		// Proceed to the next handler if chat is allowed
		next.ServeHTTP(w, r)
	})
}

// PostMessage allows a user to post a message in a coterie.
func PostMessage(w http.ResponseWriter, r *http.Request) {
	db, ok := r.Context().Value("db").(*mongo.Client)
	if !ok {
		http.Error(w, `{"error": "Database connection not available"}`, http.StatusInternalServerError)
		return
	}

	coterieCollection := db.Database("SocialFlux").Collection("coterie")
	userCollection := db.Database("SocialFlux").Collection("users")
	messageCollection := db.Database("SocialFlux").Collection("messages")

	// Extract the coterieName, userID, and content from the query
	coterieName := r.URL.Query().Get("coterieName")
	userIDStr := r.URL.Query().Get("userID")
	content := r.URL.Query().Get("content")

	if coterieName == "" || userIDStr == "" || content == "" {
		http.Error(w, `{"error": "Missing required fields: coterieName, userID, and content are required"}`, http.StatusBadRequest)
		return
	}

	// Validate user ID (UUID)
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		http.Error(w, `{"error": "Invalid user ID format"}`, http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Verify user exists
	var user types.User
	err = userCollection.FindOne(ctx, bson.M{"id": userID}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			http.Error(w, `{"error": "User not found"}`, http.StatusNotFound)
			return
		}
		http.Error(w, `{"error": "Error verifying user: `+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	// Find the coterie
	var coterie types.Coterie
	err = coterieCollection.FindOne(ctx, bson.M{"name": coterieName}).Decode(&coterie)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			http.Error(w, `{"error": "Coterie not found"}`, http.StatusNotFound)
			return
		}
		http.Error(w, `{"error": "Error finding coterie: `+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	// Check if the user is a member of the coterie
	isMember := false
	for _, member := range coterie.Members {
		if member == userIDStr {
			isMember = true
			break
		}
	}

	if !isMember {
		http.Error(w, `{"error": "You are not a member of this coterie"}`, http.StatusForbidden)
		return
	}

	// Encrypt the content
	encryptedContent, err := middlewares.EncryptAES(content)
	if err != nil {
		http.Error(w, `{"error": "Failed to encrypt message: `+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	// Create the message object
	message := types.Message{
		Coterie:   coterieName,
		UserID:    userID.String(),
		Content:   encryptedContent,
		CreatedAt: time.Now(),
	}

	// Insert the message into the messages collection
	_, err = messageCollection.InsertOne(ctx, message)
	if err != nil {
		http.Error(w, `{"error": "Failed to post message: `+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"message": "Message posted successfully"}`))
}

// FetchMessages retrieves messages for a specific coterie.
func FetchMessages(w http.ResponseWriter, r *http.Request) {
	db, ok := r.Context().Value("db").(*mongo.Client)
	if !ok {
		http.Error(w, `{"error": "Database connection not available"}`, http.StatusInternalServerError)
		return
	}

	coterieCollection := db.Database("SocialFlux").Collection("coterie")
	userCollection := db.Database("SocialFlux").Collection("users")
	messageCollection := db.Database("SocialFlux").Collection("messages")

	// Extract the coterieName and userID
	coterieName := r.URL.Query().Get("coterieName")
	userIDStr := r.URL.Query().Get("userID")

	if coterieName == "" || userIDStr == "" {
		http.Error(w, `{"error": "Missing required fields: coterieName and userID are required"}`, http.StatusBadRequest)
		return
	}

	// Validate user ID (UUID)
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		http.Error(w, `{"error": "Invalid user ID format"}`, http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Verify user exists
	var user types.User
	err = userCollection.FindOne(ctx, bson.M{"id": userID}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			http.Error(w, `{"error": "User not found"}`, http.StatusNotFound)
			return
		}
		http.Error(w, `{"error": "Error verifying user: `+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	// Find the coterie
	var coterie types.Coterie
	err = coterieCollection.FindOne(ctx, bson.M{"name": coterieName}).Decode(&coterie)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			http.Error(w, `{"error": "Coterie not found"}`, http.StatusNotFound)
			return
		}
		http.Error(w, `{"error": "Error finding coterie: `+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	// Check if the user is a member of the coterie
	isMember := false
	for _, member := range coterie.Members {
		if member == userIDStr {
			isMember = true
			break
		}
	}

	if !isMember {
		http.Error(w, `{"error": "You are not a member of this coterie"}`, http.StatusForbidden)
		return
	}

	// Fetch the messages from the coterie, sorted by creation date (descending)
	cursor, err := messageCollection.Find(ctx, bson.M{"coterie": coterieName}, options.Find().SetSort(bson.D{{Key: "createdAt", Value: -1}}))
	if err != nil {
		http.Error(w, `{"error": "Failed to fetch messages: `+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	defer cursor.Close(ctx)

	var messages []types.Message
	if err = cursor.All(ctx, &messages); err != nil {
		http.Error(w, `{"error": "Error decoding messages: `+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	// Modify the message format by removing userID and _id, adding author details
	var formattedMessages []map[string]interface{}
	for _, message := range messages {
		// Decrypt the content
		decryptedContent, err := middlewares.DecryptAES(message.Content)
		if err != nil {
			http.Error(w, `{"error": "Error decrypting message content: `+err.Error()+`"}`, http.StatusInternalServerError)
			return
		}

		// Get the user who posted the message
		var messageUser types.User
		err = userCollection.FindOne(ctx, bson.M{"id": message.UserID}).Decode(&messageUser)
		if err != nil {
			http.Error(w, `{"error": "Error fetching user data: `+err.Error()+`"}`, http.StatusInternalServerError)
			return
		}

		// Format the message with author details
		formattedMessages = append(formattedMessages, map[string]interface{}{
			"content":   string(decryptedContent),
			"createdAt": message.CreatedAt,
			"author": map[string]interface{}{
				"username":       messageUser.Username,
				"profilePicture": messageUser.ProfilePicture,
			},
		})
	}

	// Return the formatted messages as JSON
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(formattedMessages); err != nil {
		http.Error(w, `{"error": "Failed to encode messages: `+err.Error()+`"}`, http.StatusInternalServerError)
	}
}

func HavokRoutes(r *chi.Mux) {
	r.With(CheckCoterieChatAllowed).Post("/new/message", middlewares.DiscordErrorReport(http.HandlerFunc(PostMessage)).ServeHTTP)
	r.With(CheckCoterieChatAllowed).Get("/messages/@all", middlewares.DiscordErrorReport(http.HandlerFunc(FetchMessages)).ServeHTTP)
}
