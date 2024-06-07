package routes

import (
	"context"
	"fmt"
	"time"

	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// Define Post structure
type Post struct {
	ID             string             `bson:"_id" json:"_id"`
	Title          string             `bson:"title" json:"title"`
	Content        string             `bson:"content" json:"content"`
	AuthorID       primitive.ObjectID `bson:"author" json:"-"`
	Author         Author             `bson:"-" json:"author"`
	ImageURL       string             `bson:"imageUrl" json:"imageUrl"`
	Hearts         []string           `bson:"hearts" json:"hearts"`
	CreatedAt      time.Time          `bson:"createdAt" json:"createdAt"`
	Comments       []Comment          `bson:"comments" json:"comments"`
	CommentNumber  int                `bson:"commentNumber" json:"commentNumber"`
	IsVerified     bool               `bson:"isVerified" json:"isVerified"`
	IsDeveloper    bool               `json:"isDeveloper"`
	IsPartner      bool               `json:"isPartner"`
	IsOwner        bool               `json:"isOwner"`
	IsOrganisation bool               `json:"isOrganisation"`
	TimeAgo        string             `bson:"timeAgo" json:"timeAgo"`
}

// Define Comment structure
type Comment struct {
	Content    string             `bson:"content" json:"content"`
	Replies    []string           `bson:"replies" json:"replies"`
	ID         string             `bson:"_id" json:"_id"`
	Author     primitive.ObjectID `bson:"author" json:"-"`
	AuthorName string             `bson:"-" json:"author"`
}

// Define Author structure
type Author struct {
	ID             primitive.ObjectID `bson:"_id,omitempty" json:"-"`
	IsVerified     bool               `json:"isVerified"`
	IsOrganisation bool               `json:"isOrganisation"`
	IsDeveloper    bool               `json:"isDeveloper"`
	IsPartner      bool               `json:"isPartner"`
	IsOwner        bool               `json:"isOwner"`
	Username       string             `bson:"username" json:"username"`
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

	// Sort by CreatedAt in descending order
	findOptions := options.Find().SetSort(bson.D{{Key: "createdAt", Value: -1}})
	cursor, err := postsCollection.Find(ctx, bson.M{}, findOptions)
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
		err := usersCollection.FindOne(ctx, bson.M{"_id": post.AuthorID}).Decode(&author)
		if err != nil {
			// Handle error (author not found)
			posts[i].Author = Author{} // or set to default if necessary
			continue
		}

		posts[i].Author.ID = post.AuthorID
		posts[i].Author.Username = author.Username
		posts[i].Author.IsVerified = author.IsVerified
		posts[i].Author.IsOrganisation = author.IsOrganisation
		posts[i].Author.IsDeveloper = author.IsDeveloper
		posts[i].Author.IsOwner = author.IsOwner
		posts[i].Author.IsPartner = author.IsPartner

		// Calculate time ago
		posts[i].TimeAgo = calculateTimeAgo(post.CreatedAt)

		// Calculate number of comments
		posts[i].CommentNumber = len(post.Comments)

		// Update comments with author usernames
		for j, comment := range posts[i].Comments {
			var commenter Author
			err := usersCollection.FindOne(ctx, bson.M{"_id": comment.Author}).Decode(&commenter)
			if err != nil {
				// Handle error (commenter not found)
				posts[i].Comments[j].AuthorName = "" // or handle as needed
				continue
			}
			posts[i].Comments[j].AuthorName = commenter.Username
		}
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
