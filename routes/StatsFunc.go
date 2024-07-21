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

	userCollection := db.Database("SocialFlux").Collection("users")

	countOptions := options.Count()
	totaluser, err := userCollection.CountDocuments(context.Background(), bson.M{}, countOptions)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Error counting registered users",
		})
	}

	return c.JSON(fiber.Map{"total_registered_user": totaluser})
}

func TotalPartnersCount(c *fiber.Ctx) error {
	db, ok := c.Locals("db").(*mongo.Client)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Database connection not available",
		})
	}

	partnerCollection := db.Database("SocialFlux").Collection("partners")

	countOptions := options.Count()
	totalpartner, err := partnerCollection.CountDocuments(context.Background(), bson.M{}, countOptions)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Error counting partners",
		})
	}

	return c.JSON(fiber.Map{"total_partner": totalpartner})
}

func TotalPostsCount(c *fiber.Ctx) error {
	db, ok := c.Locals("db").(*mongo.Client)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Database connection not available",
		})
	}

	partnerCollection := db.Database("SocialFlux").Collection("posts")

	countOptions := options.Count()
	totalpartner, err := partnerCollection.CountDocuments(context.Background(), bson.M{}, countOptions)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Error counting posts",
		})
	}

	return c.JSON(fiber.Map{"total_posts": totalpartner})
}

func Stats(app *fiber.App) {
	app.Get("/stats/posts/@all", TotalPostsCount)
	app.Get("/stats/partners/@all", TotalPartnersCount)
	app.Get("/stats/users/@all", RegistergedUserNum)
}
