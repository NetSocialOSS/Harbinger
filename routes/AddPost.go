package routes

import (
	"context"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"netsocial/types"

	"github.com/gofiber/fiber/v2"
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

func AddPost(c *fiber.Ctx) error {
	db, ok := c.Locals("db").(*mongo.Client)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Database connection not available",
		})
	}

	postsCollection := db.Database("SocialFlux").Collection("posts")
	usersCollection := db.Database("SocialFlux").Collection("users")
	coteriesCollection := db.Database("SocialFlux").Collection("coterie")

	title := c.Query("title")
	content := c.Query("content")
	userId := c.Query("userId")
	image := c.Query("image")
	coterieName := c.Query("coterie")

	if title == "" || content == "" || userId == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Title, content, and user ID are required",
		})
	}

	authorID, err := primitive.ObjectIDFromHex(userId)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid user ID format",
		})
	}

	// Check if the user is banned
	var user types.User
	err = usersCollection.FindOne(c.Context(), bson.M{"_id": authorID}).Decode(&user)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to fetch user information",
		})
	}

	if user.IsBanned {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"message": "Hey there, you are banned from using NetSocial's services.",
		})
	}

	if coterieName != "" {
		// Check if the user is a member of the coterie
		var coterie types.Coterie
		err = coteriesCollection.FindOne(c.Context(), bson.M{"name": coterieName}).Decode(&coterie)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to fetch coterie information",
			})
		}

		isMember := false
		for _, memberID := range coterie.Members {
			if memberID == userId {
				isMember = true
				break
			}
		}

		if !isMember {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": "User is not a member of the coterie",
			})
		}
	}

	// Generate a unique post ID
	postID, err := generateUniqueID(postsCollection)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to generate unique post ID",
		})
	}

	// Create the post document
	post := bson.M{
		"_id":       postID,
		"title":     title,
		"content":   content,
		"author":    authorID,
		"hearts":    []string{},
		"createdAt": time.Now(),
	}

	if coterieName != "" {
		post["coterie"] = coterieName
	}

	// Add the Image field only if image URLs are provided
	if image != "" {
		imageArray := strings.FieldsFunc(image, func(r rune) bool {
			return r == ','
		})
		post["image"] = imageArray
	}

	_, err = postsCollection.InsertOne(c.Context(), post)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to create post",
		})
	}

	return c.Status(http.StatusCreated).JSON(fiber.Map{
		"message": "Post successfully created!",
	})
}
