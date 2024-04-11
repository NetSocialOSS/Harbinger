package routes

import (
	"context"

	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func RegistergedUserNum(c *fiber.Ctx) error {
	db, ok := c.Locals("db").(*mongo.Client)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Database connection not available",
		})
	}

	userCollection := db.Database("Socialflux").Collection("usersDB1")

	countOptions := options.Count()
	totaluser, err := userCollection.CountDocuments(context.Background(), bson.M{}, countOptions)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Error counting registered users",
		})
	}

	return c.JSON(fiber.Map{"total_registered_user": totaluser})
}
