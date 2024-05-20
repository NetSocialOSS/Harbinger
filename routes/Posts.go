package routes

import (
	"context"
	"fmt"
	"time"

	"socialflux/types"

	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// Function to handle fetching a single post by ID
func GetPostById(c *fiber.Ctx) error {
	// Get the post ID from the URL parameter
	postID := c.Params("id")

	// Access MongoDB client from Fiber context
	db, ok := c.Locals("db").(*mongo.Client)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Database connection not available",
		})
	}

	// Access MongoDB collection for posts
	postsCollection := db.Database("SocialFlux").Collection("posts")

	// Define options to customize the query
	opts := options.FindOne().SetProjection(bson.M{
		"title":     1,
		"content":   1,
		"author":    1,
		"createdAt": 1,
		"hearts":    1,
		"imageUrl":  1,
		"comments":  1, // Include comments in projection
	})

	// Find the post by its ID
	var post types.Post
	if err := postsCollection.FindOne(context.Background(), bson.M{"_id": postID}, opts).Decode(&post); err != nil {
		if err == mongo.ErrNoDocuments {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error": "Post not found",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": fmt.Sprintf("Failed to fetch post: %v", err),
		})
	}

	// Fetch author details from the users collection
	usersCollection := db.Database("SocialFlux").Collection("users")
	var author types.Author
	if err := usersCollection.FindOne(context.Background(), bson.M{"_id": post.Author}).Decode(&author); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": fmt.Sprintf("Failed to fetch author details: %v", err),
		})
	}

	// Format the time ago
	timeAgo := TimeAgo(post.CreatedAt)

	// Format comments
	var formattedComments []map[string]interface{}
	for _, comment := range post.Comments {
		// Fetch author details from the users collection
		var author types.Author
		if err := usersCollection.FindOne(context.Background(), bson.M{"_id": comment.Author}).Decode(&author); err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": fmt.Sprintf("Failed to fetch author details: %v", err),
			})
		}

		formattedComment := map[string]interface{}{
			"content": comment.Content,
			"author": map[string]interface{}{
				"_id":       comment.Author.Hex(), // Convert ObjectID to its hexadecimal representation
				"username":  author.Username,
				"createdAt": author.CreatedAt,
			},
			"_id":     comment.ID.Hex(), // Convert ObjectID to its hexadecimal representation
			"replies": comment.Replies,
		}
		formattedComments = append(formattedComments, formattedComment)
	}

	// Construct the response data
	responseData := map[string]interface{}{
		"_id":       post.ID,
		"title":     post.Title,
		"content":   post.Content,
		"author":    author,
		"createdAt": post.CreatedAt,
		"timeAgo":   timeAgo,
		"hearts":    post.Hearts,
		"comments":  formattedComments,
		"imageUrl":  post.ImageURL,
	}

	return c.JSON(responseData)
}

// Function to calculate time ago
func TimeAgo(createdAt time.Time) string {
	now := time.Now().UTC()
	diff := now.Sub(createdAt)

	days := int(diff.Hours() / 24)
	if days > 0 {
		return fmt.Sprintf("%d days ago", days)
	}

	hours := int(diff.Hours())
	if hours > 0 {
		return fmt.Sprintf("%d hours ago", hours)
	}

	minutes := int(diff.Minutes())
	if minutes > 0 {
		return fmt.Sprintf("%d minutes ago", minutes)
	}

	return "Just now"
}

