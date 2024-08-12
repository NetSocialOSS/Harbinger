package routes

import (
	"context"

	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func getCount(c *fiber.Ctx, collectionName string, fieldName string) error {
	db, ok := c.Locals("db").(*mongo.Client)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Database connection not available",
		})
	}

	collection := db.Database("SocialFlux").Collection(collectionName)

	countOptions := options.Count()
	total, err := collection.CountDocuments(context.Background(), bson.M{}, countOptions)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Error counting documents",
		})
	}

	return c.JSON(fiber.Map{fieldName: total})
}

func RegistergedUserNum(c *fiber.Ctx) error {
	return getCount(c, "users", "total_registered_user")
}

func TotalPartnersCount(c *fiber.Ctx) error {
	return getCount(c, "partners", "total_partner")
}

func TotalPostsCount(c *fiber.Ctx) error {
	return getCount(c, "posts", "total_posts")
}

func TotalCoterieCount(c *fiber.Ctx) error {
	return getCount(c, "coterie", "total_coteries")
}

func Stats(app *fiber.App) {
	app.Get("/stats/posts/@all", TotalPostsCount)
	app.Get("/stats/coterie/@all", TotalCoterieCount)
	app.Get("/stats/partners/@all", TotalPartnersCount)
	app.Get("/stats/users/@all", RegistergedUserNum)
}
