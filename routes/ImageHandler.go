package routes

import (
	"context"
	"encoding/base64"
	"time"

	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

// ProfilePictureHandler handles requests to display a user's profile picture
func ProfilePictureHandler(c *fiber.Ctx) error {
	// Extract the user ID from the URL
	userIDParam := c.Params("userId")

	// Parse the user ID into an ObjectID
	userID, err := primitive.ObjectIDFromHex(userIDParam)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid user ID format",
		})
	}

	// Retrieve the database client from Fiber context
	db, ok := c.Locals("db").(*mongo.Client)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Database connection not available",
		})
	}

	// Access the users collection
	usersCollection := db.Database("test").Collection("users")

	// Define a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Find the user by ID
	var user struct {
		ProfilePicture string `bson:"profilePicture"`
	}
	err = usersCollection.FindOne(ctx, bson.M{"_id": userID}).Decode(&user)
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
	// Extract the user ID from the URL
	userIDParam := c.Params("userId")

	// Parse the user ID into an ObjectID
	userID, err := primitive.ObjectIDFromHex(userIDParam)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid user ID format",
		})
	}

	// Retrieve the database client from Fiber context
	db, ok := c.Locals("db").(*mongo.Client)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Database connection not available",
		})
	}

	// Access the users collection
	usersCollection := db.Database("test").Collection("users")

	// Define a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Find the user by ID
	var user struct {
		ProfileBanner string `bson:"profileBanner"`
	}
	err = usersCollection.FindOne(ctx, bson.M{"_id": userID}).Decode(&user)
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
