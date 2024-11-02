package routes

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"netsocial/types"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// Get the AES key from environment variable
func getAESKey() ([]byte, error) {
	key := os.Getenv("aeskey")
	if len(key) == 0 {
		return nil, errors.New("AES key is not set in environment variables")
	}
	return []byte(key), nil
}

// PKCS7 padding
func pad(data []byte) []byte {
	padLen := aes.BlockSize - len(data)%aes.BlockSize
	pad := bytes.Repeat([]byte{byte(padLen)}, padLen)
	return append(data, pad...)
}

// Remove PKCS7 padding
func unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("data to unpad is empty")
	}
	padLen := data[len(data)-1]
	if int(padLen) > len(data) || padLen > aes.BlockSize {
		return nil, errors.New("invalid padding size")
	}
	return data[:len(data)-int(padLen)], nil
}

// Encrypt the given plaintext using AES
func encrypt(plainText []byte) (string, error) {
	key, err := getAESKey()
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// Pad the plaintext
	plainText = pad(plainText)

	ciphertext := make([]byte, aes.BlockSize+len(plainText))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plainText)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt the given ciphertext using AES
func decrypt(cipherText string) ([]byte, error) {
	key, err := getAESKey()
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext, _ := base64.StdEncoding.DecodeString(cipherText)
	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)

	// Unpad the decrypted data
	return unpad(ciphertext)
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

	// Validate and convert user ID
	userID, err := primitive.ObjectIDFromHex(userIDStr)
	if err != nil {
		http.Error(w, `{"error": "Invalid user ID format"}`, http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Verify user exists
	var user types.User
	err = userCollection.FindOne(ctx, bson.M{"_id": userID}).Decode(&user)
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

	// Check if chat is allowed in the coterie
	if !coterie.IsChatAllowed {
		http.Error(w, `{"error": "Chatting is disabled for this coterie."}`, http.StatusForbidden)
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
	encryptedContent, err := encrypt([]byte(content))
	if err != nil {
		http.Error(w, `{"error": "Failed to encrypt message: `+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	// Create the message object
	message := types.Message{
		Coterie:   coterieName,
		UserID:    userID,
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

	// Validate and convert user ID
	userID, err := primitive.ObjectIDFromHex(userIDStr)
	if err != nil {
		http.Error(w, `{"error": "Invalid user ID format"}`, http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Verify user exists
	var user types.User
	err = userCollection.FindOne(ctx, bson.M{"_id": userID}).Decode(&user)
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

	// Check if chat is allowed in the coterie
	if !coterie.IsChatAllowed {
		http.Error(w, `{"error": "Chatting is disabled for this coterie."}`, http.StatusForbidden)
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
		decryptedContent, err := decrypt(message.Content)
		if err != nil {
			http.Error(w, `{"error": "Error decrypting message content: `+err.Error()+`"}`, http.StatusInternalServerError)
			return
		}

		// Get the user who posted the message
		var messageUser types.User
		err = userCollection.FindOne(ctx, bson.M{"_id": message.UserID}).Decode(&messageUser)
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
				"profileBanner":  messageUser.ProfileBanner,
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
	r.Post("/new/message", PostMessage)
	r.Get("/messages/@all", FetchMessages)
}
