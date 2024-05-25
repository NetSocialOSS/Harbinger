package routes

import (
	"context"
	"fmt"
	"time"

	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

// Define Post structure
type Post struct {
	ID            string             `bson:"_id" json:"_id"`
	Title         string             `bson:"title" json:"title"`
	Content       string             `bson:"content" json:"content"`
	AuthorName    string             `bson:"authorName" json:"authorName"`
	Author        primitive.ObjectID `bson:"author" json:"author"`
	ImageURL      string             `bson:"imageUrl" json:"imageUrl"`
	Hearts        []string           `bson:"hearts" json:"hearts"`
	CreatedAt     time.Time          `bson:"createdAt" json:"createdAt"`
	Comments      []Comment          `bson:"comments" json:"comments"`
	CommentNumber int                `bson:"commentNumber" json:"commentNumber"`
	IsVerified    bool               `bson:"isVerified" json:"isVerified"`
	TimeAgo       string             `bson:"timeAgo" json:"timeAgo"`
}

// Define Comment structure
type Comment struct {
	Content string   `bson:"content" json:"content"`
	Author  string   `bson:"author" json:"author"`
	Replies []string `bson:"replies" json:"replies"`
	ID      string   `bson:"_id" json:"_id"`
}

// Define Author structure
type Author struct {
	ID         primitive.ObjectID `bson:"_id" json:"_id"`
	IsVerified bool               `json:"isVerified"`
	Username   string             `bson:"username" json:"username"`
}

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

	cursor, err := postsCollection.Find(ctx, bson.M{})
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	defer cursor.Close(ctx)

	var posts []Post
	if err := cursor.All(ctx, &posts); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	for i, post := range posts {
		var author Author
		err := usersCollection.FindOne(ctx, bson.M{"_id": post.Author}).Decode(&author)
		if err != nil {
			// Handle error (author not found)
			posts[i].Author = primitive.NilObjectID // or some default value
			posts[i].AuthorName = ""                // or set to default if necessary
			posts[i].IsVerified = false             // or set to default if necessary
			continue
		}

		posts[i].AuthorName = author.Username
		posts[i].IsVerified = author.IsVerified

		// Calculate time ago
		posts[i].TimeAgo = calculateTimeAgo(post.CreatedAt)

		// Calculate number of comments
		posts[i].CommentNumber = len(post.Comments)
	}

	return c.JSON(posts)
}

func calculateTimeAgo(createdAt time.Time) string {
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
