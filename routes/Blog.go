package routes

import (
	"context"
	"log"

	"socialflux/types"

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

	servCollection := db.Database("SocialFlux").Collection("posts")

	// Fetch all documents from the collection
	var servers []types.BlogPost
	cursor, err := servCollection.Find(context.Background(), bson.D{})
	if err != nil {
		log.Println("Error fetching server posts:", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to fetch server posts",
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
		servers = append(servers, server)
	}

	if err := cursor.Err(); err != nil {
		log.Println("Error with cursor:", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Cursor error",
		})
	}

	// Send the JSON response
	return c.JSON(servers)
}
