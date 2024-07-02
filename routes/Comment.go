package routes

import (
	"context"
	"log"

	"netsocial/types"

	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// AddComment adds a new comment to a post
func AddComment(c *fiber.Ctx) error {
	// Get the MongoDB client from the context
	db, ok := c.Locals("db").(*mongo.Client)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Database connection not available",
		})
	}

	// Parse query parameters
	postID := c.Query("id")
	content := c.Query("content")
	authorIDStr := c.Query("author")

	// Validate the inputs
	if postID == "" || content == "" || authorIDStr == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Missing required query parameters",
		})
	}

	// Convert authorIDStr to ObjectID
	authorObjectID, err := primitive.ObjectIDFromHex(authorIDStr)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid author ID",
		})
	}

	// Create a new comment
	comment := types.Comment{
		ID:      primitive.NewObjectID(),
		Content: content,
		Author:  authorObjectID,
	}

	// Define collections
	postsCollection := db.Database("SocialFlux").Collection("posts")
	usersCollection := db.Database("SocialFlux").Collection("users")

	// Verify that the author exists
	var author types.User
	err = usersCollection.FindOne(context.Background(), bson.M{"_id": authorObjectID}).Decode(&author)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Author not found",
			})
		}
		log.Printf("Error finding author: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to verify author",
		})
	}

	// Update the post with the new comment
	filter := bson.M{"_id": postID} // Use postID as a string
	update := bson.M{"$push": bson.M{"comments": comment}}
	opts := options.FindOneAndUpdate().SetReturnDocument(options.After)

	var updatedPost types.Post
	err = postsCollection.FindOneAndUpdate(context.Background(), filter, update, opts).Decode(&updatedPost)
	if err != nil {
		log.Printf("Error updating post: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to add comment to post",
		})
	}

	return c.Status(fiber.StatusOK).JSON(updatedPost)
}
