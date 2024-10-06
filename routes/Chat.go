package routes

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/limiter"
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
func PostMessage(c *fiber.Ctx) error {
	db, ok := c.Locals("db").(*mongo.Client)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Database connection not available",
		})
	}

	coterieCollection := db.Database("SocialFlux").Collection("coterie")
	userCollection := db.Database("SocialFlux").Collection("users")
	messageCollection := db.Database("SocialFlux").Collection("messages")

	// Extract the coterieName, userID, and content from the query
	coterieName := c.Query("coterieName")
	userIDStr := c.Query("userID")
	content := c.Query("content")

	if coterieName == "" || userIDStr == "" || content == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Missing required fields: coterieName, userID, and content are required",
		})
	}

	// Validate and convert user ID
	userID, err := primitive.ObjectIDFromHex(userIDStr)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid user ID format",
		})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Verify user exists
	var user bson.M
	err = userCollection.FindOne(ctx, bson.M{"_id": userID}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error": "User not found",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Error verifying user: " + err.Error(),
		})
	}

	// Find the coterie
	var coterie bson.M
	err = coterieCollection.FindOne(ctx, bson.M{"name": coterieName}).Decode(&coterie)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error": "Coterie not found",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Error finding coterie: " + err.Error(),
		})
	}

	// Check if the user is a member of the coterie
	members, ok := coterie["members"].(primitive.A)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Invalid coterie member data",
		})
	}

	isMember := false
	for _, member := range members {
		if memberStr, ok := member.(string); ok {
			if memberStr == userIDStr {
				isMember = true
				break
			}
		}
	}

	if !isMember {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error": "You are not a member of this coterie",
		})
	}

	// Encrypt the content
	encryptedContent, err := encrypt([]byte(content))
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to encrypt message: " + err.Error(),
		})
	}

	// Create the message
	message := bson.M{
		"coterie":   coterieName,
		"userID":    userID,
		"content":   encryptedContent,
		"createdAt": time.Now(),
	}

	// Insert the message into the messages collection
	_, err = messageCollection.InsertOne(ctx, message)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to post message: " + err.Error(),
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "Message posted successfully",
	})
}

// FetchMessages retrieves messages for a specific coterie.
func FetchMessages(c *fiber.Ctx) error {
	db, ok := c.Locals("db").(*mongo.Client)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Database connection not available",
		})
	}

	coterieCollection := db.Database("SocialFlux").Collection("coterie")
	userCollection := db.Database("SocialFlux").Collection("users")
	messageCollection := db.Database("SocialFlux").Collection("messages")

	// Extract the coterieName and userID
	coterieName := c.Query("coterieName")
	userIDStr := c.Query("userID")

	if coterieName == "" || userIDStr == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Missing required fields: coterieName and userID are required",
		})
	}

	// Validate and convert user ID
	userID, err := primitive.ObjectIDFromHex(userIDStr)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid user ID format",
		})
	}

	// Verify user exists
	var user bson.M
	err = userCollection.FindOne(context.Background(), bson.M{"_id": userID}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error": "User not found",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Error verifying user: " + err.Error(),
		})
	}

	// Find the coterie
	var coterie bson.M
	err = coterieCollection.FindOne(context.Background(), bson.M{"name": coterieName}).Decode(&coterie)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error": "Coterie not found",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Error finding coterie: " + err.Error(),
		})
	}

	// Check if the user is a member of the coterie
	members, ok := coterie["members"].(primitive.A)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Invalid coterie member data",
		})
	}
	isMember := false
	for _, member := range members {
		if memberStr, ok := member.(string); ok {
			if memberStr == userIDStr {
				isMember = true
				break
			}
		}
	}

	if !isMember {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error": "You are not a member of this coterie",
		})
	}

	// Fetch the messages from the coterie, sorted by creation date (descending)
	cursor, err := messageCollection.Find(context.Background(), bson.M{"coterie": coterieName}, options.Find().SetSort(bson.D{{Key: "createdAt", Value: -1}}))
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to fetch messages: " + err.Error(),
		})
	}
	defer cursor.Close(context.Background())

	var messages []bson.M
	if err = cursor.All(context.Background(), &messages); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Error decoding messages: " + err.Error(),
		})
	}

	// Modify the message format by removing userID and _id, adding author details
	var formattedMessages []fiber.Map
	for _, message := range messages {
		// Decrypt the content
		decryptedContent, err := decrypt(message["content"].(string))
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Error decrypting message content: " + err.Error(),
			})
		}

		// Get the user who posted the message
		messageUserID := message["userID"].(primitive.ObjectID)
		var messageUser bson.M
		err = userCollection.FindOne(context.Background(), bson.M{"_id": messageUserID}).Decode(&messageUser)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Error fetching user data: " + err.Error(),
			})
		}

		// Format the message with author details
		formattedMessages = append(formattedMessages, fiber.Map{
			"content":   string(decryptedContent),
			"createdAt": message["createdAt"],
			"author": fiber.Map{
				"username":       messageUser["username"],
				"profilePicture": messageUser["profilePicture"],
				"profileBanner":  messageUser["profileBanner"],
			},
		})
	}

	return c.Status(fiber.StatusOK).JSON(formattedMessages)
}

func HavokRoutes(app *fiber.App) {
	app.Post("/new/message", limiter.New(rateLimitConfig), PostMessage)
	app.Get("/messages/@all", FetchMessages)
}
