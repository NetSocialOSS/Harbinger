package routes

import (
	"context"
	"log"

	"netsocial/types"

	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

func GetPosts(c *fiber.Ctx) error {
	db, ok := c.Locals("db").(*mongo.Client)
	if !ok {
		return fiberError(c, fiber.StatusInternalServerError, "Database connection not available")
	}

	blogCollection := db.Database("SocialFlux").Collection("blogposts")

	var blogs []types.BlogPost
	cursor, err := blogCollection.Find(context.Background(), bson.D{})
	if err != nil {
		return logAndReturnError(c, "Failed to fetch blog posts", err)
	}
	defer cursor.Close(context.Background())

	if err := cursor.All(context.Background(), &blogs); err != nil {
		return logAndReturnError(c, "Failed to decode blog posts", err)
	}

	return c.JSON(blogs)
}

func fiberError(c *fiber.Ctx, status int, msg string) error {
	return c.Status(status).JSON(fiber.Map{"error": msg})
}

func logAndReturnError(c *fiber.Ctx, msg string, err error) error {
	log.Println(msg+":", err)
	return fiberError(c, fiber.StatusInternalServerError, msg)
}
