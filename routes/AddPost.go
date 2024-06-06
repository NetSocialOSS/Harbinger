package routes

import (
	"math/rand"
	"net/http"
	"time"

	"socialflux/types"

	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

// Generate a random string ID
func generateRandomID() string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	seededRand := rand.New(rand.NewSource(time.Now().UnixNano()))
	b := make([]byte, 8)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}

func AddPost(c *fiber.Ctx) error {
	// Access MongoDB client from Fiber context
	db, ok := c.Locals("db").(*mongo.Client)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Database connection not available",
		})
	}

	// Access MongoDB collection for posts
	postsCollection := db.Database("SocialFlux").Collection("posts")

	// Extract query parameters
	title := c.Query("title")
	content := c.Query("content")
	userId := c.Query("userId")
	image := c.Query("image")

	// Validate required fields
	if title == "" || content == "" || userId == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Title, content, and user ID are required",
		})
	}

	// Convert userId to ObjectID
	authorID, err := primitive.ObjectIDFromHex(userId)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid user ID format",
		})
	}

	// Create a new post
	post := types.Post{
		ID:        generateRandomID(),
		Title:     title,
		Content:   content,
		Author:    authorID,
		Image:     image,
		Hearts:    []string{},
		CreatedAt: time.Now(),
		Comments:  []types.Comment{},
	}

	// Insert the post into the database
	_, err = postsCollection.InsertOne(c.Context(), post)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to create post",
		})
	}

	// Return the created post
	return c.Status(http.StatusCreated).JSON(post)
}
