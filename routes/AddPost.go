package routes

import (
	"math/rand"
	"net/http"
	"time"

	"netsocial/types"

	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson"
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
	db, ok := c.Locals("db").(*mongo.Client)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Database connection not available",
		})
	}

	postsCollection := db.Database("SocialFlux").Collection("posts")
	usersCollection := db.Database("SocialFlux").Collection("users")

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

	post := types.Post{
		ID:        generateRandomID(),
		Title:     title,
		Content:   content,
		Author:    authorID,
		Image:     image,
		Hearts:    []string{},
		CreatedAt: time.Now(),
		Comments:  []types.Comment{},
		Coterie:   coterieName, // Include coterieName directly
	}

	_, err = postsCollection.InsertOne(c.Context(), post)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to create post",
		})
	}

	return c.Status(http.StatusCreated).JSON(post)
}
