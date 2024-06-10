package routes

import (
	"context"
	"time"

	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

// DeletePost handles the deletion of a post by its ID and author's primitive object ID
func DeletePost(c *fiber.Ctx) error {
	// Get the database connection from the context
	db, ok := c.Locals("db").(*mongo.Client)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Database connection not available",
		})
	}

	// Get the posts collection
	postsCollection := db.Database("SocialFlux").Collection("posts")

	// Extract post ID and author ID from query parameters
	postID := c.Query("postid")
	authorID := c.Query("authorid")

	// Convert the author ID to a primitive.ObjectID
	authorObjectID, err := primitive.ObjectIDFromHex(authorID)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid author ID format",
		})
	}

	// Create a filter for deleting the post
	filter := bson.M{
		"_id":    postID,
		"author": authorObjectID,
	}

	// Set a context with a timeout for the delete operation
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Perform the delete operation
	result, err := postsCollection.DeleteOne(ctx, filter)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to delete post",
		})
	}

	// Check if a post was deleted
	if result.DeletedCount == 0 {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "Post not found or you are not the author",
		})
	}

	return c.JSON(fiber.Map{
		"message": "Post deleted successfully",
	})
}
