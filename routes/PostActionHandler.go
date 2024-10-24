package routes

import (
	"context"
	"netsocial/types"

	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

// PostActions handles actions on posts such as like, unlike, and potentially more actions in the future.
func PostActions(c *fiber.Ctx) error {
	// Get the postId, userId, and action from query parameters
	postId := c.Query("postId") // postId is now treated as a string
	userId := c.Query("userId")
	action := c.Query("action")

	// Validate the action (either "like" or "unlike" currently, can expand for other actions)
	if action != "like" && action != "unlike" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid action. Action must be 'like' or 'unlike'.",
		})
	}

	// Parse userId to primitive.ObjectID
	userID, err := primitive.ObjectIDFromHex(userId)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid user ID",
		})
	}

	// Access the MongoDB client from the context
	db, ok := c.Locals("db").(*mongo.Client)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Database connection not available",
		})
	}

	// Access MongoDB collection for users
	usersCollection := db.Database("SocialFlux").Collection("users")

	// Check if the user is banned
	var user types.User
	err = usersCollection.FindOne(context.Background(), bson.M{"_id": userID}).Decode(&user)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to fetch user details",
		})
	}

	if user.IsBanned {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error": "You are banned from using NetSocial's services.",
		})
	}

	// Access MongoDB collection for posts
	postsCollection := db.Database("SocialFlux").Collection("posts")

	// Filter for the post by postId (since postId is a string, no conversion is needed)
	filter := bson.M{"_id": postId}

	// Define the update operation based on the action
	var update bson.M
	switch action {
	case "like":
		// Add the userID to the hearts array for "like" action
		update = bson.M{"$addToSet": bson.M{"hearts": userID}}
	case "unlike":
		// Remove the userID from the hearts array for "unlike" action
		update = bson.M{"$pull": bson.M{"hearts": userID}}
	}

	// Update the post with the specified action
	_, err = postsCollection.UpdateOne(context.Background(), filter, update)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to update post",
		})
	}

	// Respond with the appropriate message
	var message string
	switch action {
	case "like":
		message = "Post liked successfully"
	case "unlike":
		message = "Post unliked successfully"
	}

	return c.JSON(fiber.Map{
		"message": message,
	})
}