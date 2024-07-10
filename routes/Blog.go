package routes

import (
	"context"
	"log"

	"netsocial/types"

	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

// ServPostHandler handles requests for server posts
func GetPosts(c *fiber.Ctx) error {
	// Fetching the database client from context
	db, ok := c.Locals("db").(*mongo.Client)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Database connection not available",
		})
	}

	blogCollection := db.Database("SocialFlux").Collection("blogposts")

	// Fetch all documents from the collection
	var blogs []types.BlogPost
	cursor, err := blogCollection.Find(context.Background(), bson.D{})
	if err != nil {
		log.Println("Error fetching blog posts:", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to fetch blog posts",
		})
	}
	defer cursor.Close(context.Background())

	for cursor.Next(context.Background()) {
		var server types.BlogPost
		if err := cursor.Decode(&server); err != nil {
			log.Println("Error decoding server post:", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to decode server post",
			})
		}
		blogs = append(blogs, server)
	}

	if err := cursor.Err(); err != nil {
		log.Println("Error with cursor:", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Cursor error",
		})
	}

	// Send the JSON response
	return c.JSON(blogs)
}
