package routes

import (
	"context"
	"socialflux/types"

	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

func GetUserByName(c *fiber.Ctx) error {
	db, ok := c.Locals("db").(*mongo.Client)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database connection not available"})
	}

	username := c.Params("username")
	if username == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Name parameter is required"})
	}

	var user types.User
	userCollection := db.Database("SocialFlux").Collection("users")
	result := userCollection.FindOne(context.Background(), bson.M{"username": username})
	if result.Err() != nil {
		if result.Err() == mongo.ErrNoDocuments {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "User not found"})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Error fetching user data"})
	}

	err := result.Decode(&user)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Error decoding user data"})
	}

	// Fetch posts made by the user without comments
	var posts []types.Post
	postCollection := db.Database("SocialFlux").Collection("posts")
	cursor, err := postCollection.Find(context.TODO(), bson.M{"author": user.ID})
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to fetch posts"})
	}

	// Create a map to store user IDs and their corresponding usernames
	userIDToUsername := make(map[primitive.ObjectID]string)

	for cursor.Next(context.TODO()) {
		var post types.Post
		err := cursor.Decode(&post)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Error decoding posts data"})
		}

		// Replace user IDs in hearts with usernames
		for i, heart := range post.Hearts {
			heartID, err := primitive.ObjectIDFromHex(heart)
			if err != nil {
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Invalid heart ID"})
			}

			if username, found := userIDToUsername[heartID]; found {
				post.Hearts[i] = username
			} else {
				var heartUser types.User
				err := userCollection.FindOne(context.Background(), bson.M{"_id": heartID}).Decode(&heartUser)
				if err != nil {
					if err == mongo.ErrNoDocuments {
						post.Hearts[i] = "Unknown User"
					} else {
						return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Error fetching heart user data"})
					}
				} else {
					userIDToUsername[heartID] = heartUser.Username
					post.Hearts[i] = heartUser.Username
				}
			}
		}

		// Exclude comments from the post
		post.Comments = nil
		posts = append(posts, post)
	}

	return c.JSON(fiber.Map{
		"username":       user.Username,
		"isVerified":     user.IsVerified,
		"isOrganisation": user.IsOrganisation,
		"isDeveloper":    user.IsDeveloper,
		"isOwner":        user.IsOwner,
		"isPartner":      user.IsPartner,
		"displayname":    user.DisplayName,
		"bio":            user.Bio,
		"createdAt":      user.CreatedAt,
		"links":          user.Links,
		"posts":          posts,
	})
}
