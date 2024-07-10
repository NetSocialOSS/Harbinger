package routes

import (
	"context"
	"netsocial/types"

	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

// LikePost adds a heart to a post
func LikePost(c *fiber.Ctx) error {
	// Get the postId and likedby from query parameters
	postId := c.Query("postId")
	likedBy := c.Query("likedby")

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
			"error": "You are banned from using NetSocial's services",
		})
	}

	// Access MongoDB collection for posts
	postsCollection := db.Database("SocialFlux").Collection("posts")

	// Add the likedByID to the hearts array of the post
	filter := bson.M{"_id": postId}
	update := bson.M{"$addToSet": bson.M{"hearts": likedByID}}

	_, err = postsCollection.UpdateOne(context.Background(), filter, update)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to update post",
		})
	}

	return c.JSON(fiber.Map{
		"message": "Post liked successfully",
	})
}

// UnlikePost removes a heart from a post
func UnlikePost(c *fiber.Ctx) error {
	// Get the postId and likedby from query parameters
	postId := c.Query("postId")
	likedBy := c.Query("likedby")

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

	// Access MongoDB collection for posts
	postsCollection := db.Database("SocialFlux").Collection("posts")

	// Remove the likedByID from the hearts array of the post
	filter := bson.M{"_id": postId}
	update := bson.M{"$pull": bson.M{"hearts": likedByID}}

	_, err = postsCollection.UpdateOne(context.Background(), filter, update)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to update post",
		})
	}

	return c.JSON(fiber.Map{
		"message": "Post unliked successfully",
	})
}
