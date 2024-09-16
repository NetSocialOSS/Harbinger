package routes

import (
	"context"
	"fmt"
	"time"

	"netsocial/types"

	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func GetAllPosts(c *fiber.Ctx) error {
	db, ok := c.Locals("db").(*mongo.Client)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Database connection not available",
		})
	}

	postsCollection := db.Database("SocialFlux").Collection("posts")
	usersCollection := db.Database("SocialFlux").Collection("users")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Sort by CreatedAt in descending order
	findOptions := options.Find().SetSort(bson.D{{Key: "createdAt", Value: -1}})
	cursor, err := postsCollection.Find(ctx, bson.M{}, findOptions)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	defer cursor.Close(ctx)

	var posts []types.Post
	if err := cursor.All(ctx, &posts); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	// Create a map to store userID to username mappings
	userCache := make(map[primitive.ObjectID]string)

	for i, post := range posts {
		var author types.Author
		err := usersCollection.FindOne(ctx, bson.M{"_id": post.Author}).Decode(&author)
		if err != nil {
			// Handle error (author not found)
			posts[i].Author = primitive.ObjectID{} // or set to default if necessary
			continue
		}

		posts[i].Author = post.Author
		posts[i].AuthorName = author.Username
		posts[i].AuthorDetails = author // Set the author details

		// Calculate time ago
		posts[i].TimeAgo = calculateTimeAgo(post.CreatedAt)

		// Calculate number of comments
		posts[i].CommentNumber = len(post.Comments)

		// Remove comments from the post object
		posts[i].Comments = nil

		// Update hearts with author usernames
		for j, heart := range post.Hearts {
			userID, err := primitive.ObjectIDFromHex(heart)
			if err != nil {
				posts[i].Hearts[j] = "Unknown"
				continue
			}

			// Check if the username is already in the cache
			username, found := userCache[userID]
			if !found {
				var heartAuthor types.Author
				err := usersCollection.FindOne(ctx, bson.M{"_id": userID}).Decode(&heartAuthor)
				if err != nil {
					// Handle error (user not found)
					posts[i].Hearts[j] = "Unknown"
					continue
				}
				username = heartAuthor.Username
				userCache[userID] = username
			}

			posts[i].Hearts[j] = username
		}
	}

	return c.JSON(posts)
}

func calculateTimeAgo(createdAt time.Time) string {
	now := time.Now().UTC()
	diff := now.Sub(createdAt)

	years := int(diff.Hours() / 24 / 365)
	if years > 0 {
		return fmt.Sprintf("%d years ago", years)
	}

	months := int(diff.Hours() / 24 / 30)
	if months > 0 {
		return fmt.Sprintf("%d months ago", months)
	}

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
