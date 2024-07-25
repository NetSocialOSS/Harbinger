package routes

import (
	"context"
	"encoding/base64"
	"time"

	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

type user struct {
	ProfilePicture string `bson:"profilePicture"`
	ProfileBanner  string `bson:"profileBanner"`
}

// retrieveUserImage retrieves the base64 encoded image from the database
func retrieveUserImage(c *fiber.Ctx, imageType string) ([]byte, error) {
	username := c.Params("userId")

	db, ok := c.Locals("db").(*mongo.Client)
	if !ok {
		return nil, fiber.ErrInternalServerError
	}

	usersCollection := db.Database("SocialFlux").Collection("users")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Find the user by username
	var user user
	err := usersCollection.FindOne(ctx, bson.M{"username": username}).Decode(&user)
	if err != nil {
		return nil, fiber.ErrNotFound
	}

	var base64Image string
	switch imageType {
	case "profilePicture":
		base64Image = user.ProfilePicture
	case "profileBanner":
		base64Image = user.ProfileBanner
	}

	if base64Image == "" {
		return nil, fiber.ErrNotFound
	}

	// Decode Base64 string to image
	decoded, err := base64.StdEncoding.DecodeString(base64Image)
	if err != nil {
		return nil, fiber.ErrInternalServerError
	}

	return decoded, nil
}

// ProfilePictureHandler handles requests to display a user's profile picture
func ProfilePictureHandler(c *fiber.Ctx) error {
	decodedImage, err := retrieveUserImage(c, "profilePicture")
	if err != nil {
		return c.Status(err.(*fiber.Error).Code).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	// Serve the image with appropriate content type
	return c.Send(decodedImage)
}

// ProfileBannerHandler handles requests to display a user's profile banner
func ProfileBannerHandler(c *fiber.Ctx) error {
	decodedImage, err := retrieveUserImage(c, "profileBanner")
	if err != nil {
		return c.Status(err.(*fiber.Error).Code).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	// Serve the image with appropriate content type
	return c.Send(decodedImage)
}

// Image sets up the routes for profile pictures and banners
func Image(app *fiber.App) {
	app.Get("/profile/:userId/image", ProfilePictureHandler)
	app.Get("/profile/:userId/banner", ProfileBannerHandler)
}
