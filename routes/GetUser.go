package routes

import (
	"context"
	"socialflux/types"

	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
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

	// Fetch posts made by the user without comments, sorted by createdAt in descending order
	var posts []types.Post
	postCollection := db.Database("SocialFlux").Collection("posts")
	cursor, err := postCollection.Find(context.TODO(), bson.M{"author": user.ID}, options.Find().SetSort(bson.D{{"createdAt", -1}}))
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to fetch posts"})
	}

	// Create a map to store user IDs and their corresponding usernames
	userIDToUsername := make(map[primitive.ObjectID]string)

	// Utility function to get username from ID
	getUsername := func(id primitive.ObjectID) (string, error) {
		if username, found := userIDToUsername[id]; found {
			return username, nil
		}
		var u types.User
		err := userCollection.FindOne(context.Background(), bson.M{"_id": id}).Decode(&u)
		if err != nil {
			if err == mongo.ErrNoDocuments {
				return "Unknown User", nil
			}
			return "", err
		}
		userIDToUsername[id] = u.Username
		return u.Username, nil
	}

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
			username, err := getUsername(heartID)
			if err != nil {
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Error fetching heart user data"})
			}
			post.Hearts[i] = username
		}

		// Exclude comments from the post
		post.Comments = nil
		posts = append(posts, post)
	}

	// Convert followers and following from IDs to usernames
	var followersUsernames, followingUsernames []string

	for _, followerID := range user.Followers {
		followerObjectID, err := primitive.ObjectIDFromHex(followerID)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Invalid follower ID"})
		}
		username, err := getUsername(followerObjectID)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Error fetching follower user data"})
		}
		followersUsernames = append(followersUsernames, username)
	}

	for _, followingID := range user.Following {
		followingObjectID, err := primitive.ObjectIDFromHex(followingID)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Invalid following ID"})
		}
		username, err := getUsername(followingObjectID)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Error fetching following user data"})
		}
		followingUsernames = append(followingUsernames, username)
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
		"followersCount": len(user.Followers),
		"followingCount": len(user.Following),
		"followers":      followersUsernames,
		"following":      followingUsernames,
		"links":          user.Links,
		"posts":          posts,
	})
}
