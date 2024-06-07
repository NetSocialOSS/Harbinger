package routes

import (
	"context"
	"encoding/base64"
	"time"

	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

// ProfilePictureHandler handles requests to display a user's profile picture
func ProfilePictureHandler(c *fiber.Ctx) error {
	// Extract the username from the URL
	username := c.Params("userId")

	// Retrieve the database client from Fiber context
	db, ok := c.Locals("db").(*mongo.Client)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Database connection not available",
		})
	}

	// Access the users collection
	usersCollection := db.Database("SocialFlux").Collection("users")

	// Define a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Find the user by username
	var user struct {
		ProfilePicture string `bson:"profilePicture"`
	}
	err := usersCollection.FindOne(ctx, bson.M{"username": username}).Decode(&user)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "User not found",
		})
	}

	// Check if profile picture is not empty
	if user.ProfilePicture == "" {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "Profile picture not found for this user",
		})
	}

	// Decode Base64 string to image
	decoded, err := base64.StdEncoding.DecodeString(user.ProfilePicture)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to decode profile picture",
		})
	}

	// Serve the image
	return c.Type("jpg").Send(decoded)
}

// ProfileBannerHandler handles requests to display a user's profile banner
func ProfileBannerHandler(c *fiber.Ctx) error {
	// Extract the username from the URL
	username := c.Params("userId")

	// Retrieve the database client from Fiber context
	db, ok := c.Locals("db").(*mongo.Client)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Database connection not available",
		})
	}

	// Access the users collection
	usersCollection := db.Database("SocialFlux").Collection("users")

	// Define a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Find the user by username
	var user struct {
		ProfileBanner string `bson:"profileBanner"`
	}
	err := usersCollection.FindOne(ctx, bson.M{"username": username}).Decode(&user)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "User not found",
		})
	}

	// Check if profile banner is not empty
	if user.ProfileBanner == "" {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "Profile banner not found for this user",
		})
	}

	// Decode Base64 string to image
	decoded, err := base64.StdEncoding.DecodeString(user.ProfileBanner)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to decode profile banner",
		})
	}

	// Serve the image
	return c.Type("jpg").Send(decoded)
}

// ProfileBannerHandler handles requests to display a user's profile banner
func PostImageHandler(c *fiber.Ctx) error {
	// Extract the post ID from the URL
	postID := c.Params("postId")

	// Retrieve the database client from Fiber context
	db, ok := c.Locals("db").(*mongo.Client)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Database connection not available",
		})
	}

	// Access the posts collection
	postsCollection := db.Database("SocialFlux").Collection("posts")

	// Define a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Find the post by ID
	var post struct {
		Image string `bson:"image"`
	}
	err := postsCollection.FindOne(ctx, bson.M{"_id": postID}).Decode(&post)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error": "Post not found",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to find post",
		})
	}

	// Check if image field is empty
	if post.Image == "" {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "Image for this post is not found",
		})
	}

	// Decode Base64 string to image
	decoded, err := base64.StdEncoding.DecodeString(post.Image)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to decode image",
		})
	}

	// Serve the image
	return c.Type("jpg").Send(decoded)
}
