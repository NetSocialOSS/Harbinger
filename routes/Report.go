package routes

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/gofiber/fiber/v2"
	"github.com/gtuk/discordwebhook"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

// getReporterUsername fetches the reporter's username from the database
func getReporterUsername(c *fiber.Ctx, reporterID string) (string, error) {
	db, ok := c.Locals("db").(*mongo.Client)
	if !ok {
		return "", fmt.Errorf("database connection not available")
	}

	userCollection := db.Database("SocialFlux").Collection("users")

	// Convert reporterID string to ObjectID
	objID, err := primitive.ObjectIDFromHex(reporterID)
	if err != nil {
		return "", fmt.Errorf("invalid reporter ID format")
	}

	filter := bson.M{"_id": objID}

	var result struct {
		Username string `bson:"username"`
	}
	err = userCollection.FindOne(context.Background(), filter).Decode(&result)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return "", nil
		}
		return "", err
	}

	return result.Username, nil
}

// ReportUser handles reporting a user
func ReportUser(c *fiber.Ctx) error {
	reportedUsername := c.Query("reportedUsername")
	reporterID := c.Query("reporterID")
	reason := c.Query("reason")

	reporterUsername, err := getReporterUsername(c, reporterID)
	if err != nil {
		log.Println("Error fetching reporter username:", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to fetch reporter username"})
	}

	if reporterUsername == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid reporter ID"})
	}

	webhookURL := os.Getenv("Report_URL")

	title := "🚨 User Report 🚨"
	description := fmt.Sprintf("[Reported User: %s](https://netsocial.app/user/%s)", reportedUsername, reportedUsername)
	reporterUsernameField := "Reporter"
	reporterUsernameValue := reporterUsername
	reasonField := "Reason"
	reasonValue := reason

	embed := discordwebhook.Embed{
		Title:       &title,
		Description: &description,
		Fields: &[]discordwebhook.Field{
			{
				Name:  &reporterUsernameField,
				Value: &reporterUsernameValue,
			},
			{
				Name:  &reasonField,
				Value: &reasonValue,
			},
		},
	}

	content := fmt.Sprintf("User %s has been reported by %s for reason: %s", reportedUsername, reporterUsername, reason)
	message := discordwebhook.Message{
		Content: &content,
		Embeds:  &[]discordwebhook.Embed{embed},
	}

	err = discordwebhook.SendMessage(webhookURL, message)
	if err != nil {
		log.Println("Error sending message to Discord webhook:", err)
		return c.Status(fiber.StatusInternalServerError).SendString("Failed to report user")
	}

	return c.SendString("User reported successfully")
}

// ReportPost handles reporting a post
func ReportPost(c *fiber.Ctx) error {
	reportedPostID := c.Query("reportedPostID")
	reporterID := c.Query("reporterID")
	reason := c.Query("reason")

	reporterUsername, err := getReporterUsername(c, reporterID)
	if err != nil {
		log.Println("Error fetching reporter username:", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to fetch reporter username"})
	}

	if reporterUsername == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid reporter ID"})
	}

	db, ok := c.Locals("db").(*mongo.Client)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).SendString("Database connection not available")
	}

	postCollection := db.Database("SocialFlux").Collection("posts")

	// Check if the reportedPostID exists in the posts collection
	filter := bson.M{"_id": reportedPostID}
	var existingPost struct {
		ID string `bson:"_id,omitempty"`
	}

	err = postCollection.FindOne(context.Background(), filter).Decode(&existingPost)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid reported post ID"})
		}
		log.Println("Error checking post existence:", err)
		return c.Status(fiber.StatusInternalServerError).SendString("Failed to check post existence")
	}

	webhookURL := os.Getenv("Report_URL")

	title := "🚨 Post Report 🚨"
	description := fmt.Sprintf("[Reported Post](https://netsocial.app/post/%s)", reportedPostID)
	reporterUsernameField := "Reporter"
	reporterUsernameValue := reporterUsername
	reasonField := "Reason"
	reasonValue := reason

	embed := discordwebhook.Embed{
		Title:       &title,
		Description: &description,
		Fields: &[]discordwebhook.Field{
			{
				Name:  &reporterUsernameField,
				Value: &reporterUsernameValue,
			},
			{
				Name:  &reasonField,
				Value: &reasonValue,
			},
		},
	}

	content := fmt.Sprintf("Post %s has been reported by %s for reason: %s", reportedPostID, reporterUsername, reason)
	message := discordwebhook.Message{
		Content: &content,
		Embeds:  &[]discordwebhook.Embed{embed},
	}

	err = discordwebhook.SendMessage(webhookURL, message)
	if err != nil {
		log.Println("Error sending message to Discord webhook:", err)
		return c.Status(fiber.StatusInternalServerError).SendString("Failed to report post")
	}

	return c.SendString("Post reported successfully")
}

// ReportCoterie handles reporting a coterie
func ReportCoterie(c *fiber.Ctx) error {
	CoterieName := c.Query("Coterie")
	reporterID := c.Query("reporterID")
	reason := c.Query("reason")

	reporterUsername, err := getReporterUsername(c, reporterID)
	if err != nil {
		log.Println("Error fetching reporter username:", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to fetch reporter username"})
	}

	if reporterUsername == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid reporter ID"})
	}

	db, ok := c.Locals("db").(*mongo.Client)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).SendString("Database connection not available")
	}

	coterieCollection := db.Database("SocialFlux").Collection("coterie")

	// Check if the Coterie exists in the collection
	filter := bson.M{"name": CoterieName}
	var Coterie struct {
		ID   string `bson:"_id,omitempty"`
		Name string `json:"name"`
	}

	err = coterieCollection.FindOne(context.Background(), filter).Decode(&Coterie)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid reported coterie name"})
		}
		log.Println("Error checking coterie existence:", err)
		return c.Status(fiber.StatusInternalServerError).SendString("Failed to check coterie existence")
	}

	webhookURL := os.Getenv("Report_URL")

	title := "🚨 Coterie Report 🚨"
	description := fmt.Sprintf("[Reported Coterie](https://netsocial.app/coterie/%s)", Coterie.Name)
	reporterUsernameField := "Reporter"
	reporterUsernameValue := reporterUsername
	reasonField := "Reason"
	reasonValue := reason

	embed := discordwebhook.Embed{
		Title:       &title,
		Description: &description,
		Fields: &[]discordwebhook.Field{
			{
				Name:  &reporterUsernameField,
				Value: &reporterUsernameValue,
			},
			{
				Name:  &reasonField,
				Value: &reasonValue,
			},
		},
	}

	content := fmt.Sprintf("Coterie %s has been reported by %s for reason: %s", CoterieName, reporterUsername, reason)
	message := discordwebhook.Message{
		Content: &content,
		Embeds:  &[]discordwebhook.Embed{embed},
	}

	err = discordwebhook.SendMessage(webhookURL, message)
	if err != nil {
		log.Println("Error sending message to Discord webhook:", err)
		return c.Status(fiber.StatusInternalServerError).SendString("Failed to report coterie")
	}

	return c.SendString("Coterie reported successfully")
}
