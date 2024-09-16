package routes

import (
	"context"
	"fmt"
	"netsocial/types"

	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

func ManageBadge(c *fiber.Ctx) error {
	db, ok := c.Locals("db").(*mongo.Client)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Database connection not available",
		})
	}

	username := c.Query("username")
	action := c.Query("action")
	badge := c.Query("badge")
	modID := c.Query("modid")

	// Validate modID
	modIDHex, err := primitive.ObjectIDFromHex(modID)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid modID",
		})
	}

	// Check if the mod is an owner
	usersCollection := db.Database("SocialFlux").Collection("users")
	modFilter := bson.M{"_id": modIDHex}
	var modUser types.User
	err = usersCollection.FindOne(context.Background(), modFilter).Decode(&modUser)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Moderator not found",
		})
	}

	if !modUser.IsOwner {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error": "Permission denied. Only owners can manage badges.",
		})
	}

	// Find the user by username
	userFilter := bson.M{"username": username}
	var user types.User
	err = usersCollection.FindOne(context.Background(), userFilter).Decode(&user)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "User not found",
		})
	}

	// Update the user's badge based on action
	update := bson.M{}
	switch action {
	case "add":
		update = handleBadgeUpdate(user, badge, true)
	case "remove":
		update = handleBadgeUpdate(user, badge, false)
	default:
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid action",
		})
	}

	// Apply the update to the user
	_, err = usersCollection.UpdateOne(context.Background(), userFilter, bson.M{"$set": update})
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to update user badges",
		})
	}

	return c.JSON(fiber.Map{
		"message": fmt.Sprintf("Badge %s successfully %sed for user %s", badge, action, username),
	})
}

func handleBadgeUpdate(_ types.User, badge string, add bool) bson.M {
	switch badge {
	case "dev":
		return bson.M{"isDeveloper": add}
	case "verified":
		return bson.M{"isVerified": add}
	case "partner":
		return bson.M{"isPartner": add}
	case "owner":
		return bson.M{"isOwner": add}
	default:
		return bson.M{}
	}
}

func Admin(app *fiber.App) {
	app.Post("/admin/manage/badge", ManageBadge)
}
