package routes

import (
	"context"
	"netsocial/types"

	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

// HeartPost handles both liking and unliking a post based on the "action" query parameter.
func HeartPost(c *fiber.Ctx) error {
	// Get the postId, likedBy, and action from query parameters
	postId := c.Query("postId")
	likedBy := c.Query("likedby")
	action := c.Query("action")

	// Validate the action (either "like" or "unlike")
	if action != "like" && action != "unlike" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid action. Action must be 'like' or 'unlike'.",
		})
	}

	// Parse likedBy to primitive.ObjectID
	likedByID, err := primitive.ObjectIDFromHex(likedBy)
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
	err = usersCollection.FindOne(context.Background(), bson.M{"_id": likedByID}).Decode(&user)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to fetch user details",
		})
	}

	if user.IsBanned {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error": "Hey there, you are banned from using NetSocial's services.",
		})
	}

	// Access MongoDB collection for posts
	postsCollection := db.Database("SocialFlux").Collection("posts")

	// Filter for the post by postId
	filter := bson.M{"_id": postId}

	var update bson.M
	if action == "like" {
		// Add the likedByID to the hearts array for "like" action
		update = bson.M{"$addToSet": bson.M{"hearts": likedByID}}
	} else if action == "unlike" {
		// Remove the likedByID from the hearts array for "unlike" action
		update = bson.M{"$pull": bson.M{"hearts": likedByID}}
	}

	// Update the post with the like/unlike action
	_, err = postsCollection.UpdateOne(context.Background(), filter, update)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to update post",
		})
	}

	// Respond with the appropriate message
	var message string
	if action == "like" {
		message = "Post liked successfully"
	} else {
		message = "Post unliked successfully"
	}

	return c.JSON(fiber.Map{
		"message": message,
	})
}
