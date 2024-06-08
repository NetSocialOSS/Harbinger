package routes

import (
	"context"

	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type UserSettingsUpdate struct {
	DisplayName    string `json:"displayName,omitempty"`
	Bio            string `json:"bio,omitempty"`
	ProfilePicture string `json:"profilePicture,omitempty"`
	ProfileBanner  string `json:"profileBanner,omitempty"`
}

func UpdateProfileSettings(c *fiber.Ctx) error {
	db, ok := c.Locals("db").(*mongo.Client)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Database connection not available",
		})
	}

	userID := c.Query("userId")
	if userID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "userId query parameter is required",
		})
	}

	objID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid userID provided",
		})
	}

	// Retrieve update parameters from both query and request body
	var updateParams UserSettingsUpdate
	// Parsing query parameters
	updateParams.DisplayName = c.Query("displayName")
	updateParams.Bio = c.Query("bio")
	updateParams.ProfilePicture = c.Query("profilePicture")
	updateParams.ProfileBanner = c.Query("profileBanner")

	// Parsing request body parameters (if any)
	if err := c.BodyParser(&updateParams); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Error parsing request body",
		})
	}

	// Prepare update filter and update fields
	updateFields := bson.M{}
	if updateParams.DisplayName != "" {
		updateFields["displayName"] = updateParams.DisplayName
	}
	if updateParams.Bio != "" {
		updateFields["bio"] = updateParams.Bio
	}
	if updateParams.ProfilePicture != "" {
		updateFields["profilePicture"] = updateParams.ProfilePicture
	}
	if updateParams.ProfileBanner != "" {
		updateFields["profileBanner"] = updateParams.ProfileBanner
	}

	// Perform update operation
	usersCollection := db.Database("SocialFlux").Collection("users")
	filter := bson.M{"_id": objID}

	update := bson.M{"$set": updateFields}

	// Use UpdateOne with Upsert option to prevent overriding existing fields with empty strings
	opts := options.Update().SetUpsert(true)
	_, err = usersCollection.UpdateOne(context.Background(), filter, update, opts)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to update user profile",
		})
	}

	return c.JSON(fiber.Map{
		"message": "Profile settings updated successfully!",
	})
}
