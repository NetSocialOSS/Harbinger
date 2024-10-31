package routes

import (
	"context"
	"netsocial/types"
	"time"

	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// PostActions handles actions on posts, including like, unlike, and voting.
func PostActions(c *fiber.Ctx) error {
	// Get the postId, userId, action, and optionId from query parameters
	postId := c.Query("postId")
	userId := c.Query("userId")
	action := c.Query("action")
	optionId := c.Query("optionId")

	// Validate action (supporting "like", "unlike", and "vote")
	if action != "like" && action != "unlike" && action != "vote" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid action. Action must be 'like', 'unlike', or 'vote'.",
		})
	}

	// Parse userId to primitive.ObjectID
	userID, err := primitive.ObjectIDFromHex(userId)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid user ID",
		})
	}

	// Access MongoDB client from context
	db, ok := c.Locals("db").(*mongo.Client)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Database connection not available",
		})
	}

	// Access MongoDB collection for users
	usersCollection := db.Database("SocialFlux").Collection("users")

	// Check if the user is banned
	var user types.User
	err = usersCollection.FindOne(context.Background(), bson.M{"_id": userID}).Decode(&user)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to fetch user details",
		})
	}
	if user.IsBanned {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error": "You are banned from using NetSocial's services.",
		})
	}

	// Access MongoDB collection for posts
	postsCollection := db.Database("SocialFlux").Collection("posts")

	// Filter for the post by postId
	filter := bson.M{"_id": postId}

	switch action {
	case "like", "unlike":
		// Handle like/unlike actions
		var update bson.M
		if action == "like" {
			update = bson.M{"$addToSet": bson.M{"hearts": userID}}
		} else {
			update = bson.M{"$pull": bson.M{"hearts": userID}}
		}
		_, err = postsCollection.UpdateOne(context.Background(), filter, update)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to update post",
			})
		}
		message := "Post liked successfully"
		if action == "unlike" {
			message = "Post unliked successfully"
		}
		return c.JSON(fiber.Map{"message": message})

	case "vote":
		// Ensure the optionId is provided
		if optionId == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Option ID is required for voting",
			})
		}

		// Convert optionId to primitive.ObjectID
		optionObjectID, err := primitive.ObjectIDFromHex(optionId)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid option ID",
			})
		}

		// Fetch post and check poll expiration
		var post types.Post
		err = postsCollection.FindOne(context.Background(), filter).Decode(&post)
		if err != nil {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error": "Post not found",
			})
		}

		// Check if any poll in the post has expired
		for _, poll := range post.Poll {
			if poll.Expiration.Before(time.Now()) {
				return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
					"error": "Poll has expired; voting is not allowed",
				})
			}
		}

		// Check if the user has already voted
		pollFilter := bson.M{
			"_id":                postId,
			"poll.options.votes": bson.M{"$ne": userID.Hex()}, // Ensure user hasn't voted yet
		}

		// Update the selected option if the user hasn't voted yet
		voteUpdate := bson.M{
			"$addToSet": bson.M{"poll.$[poll].options.$[option].votes": userID.Hex()},
			"$inc":      bson.M{"poll.$[poll].options.$[option].voteCount": 1},
		}
		arrayFilters := options.Update().SetArrayFilters(options.ArrayFilters{
			Filters: []interface{}{
				bson.M{"poll._id": post.Poll[0].ID},
				bson.M{"option._id": optionObjectID},
			},
		})

		// Execute the vote update with array filters
		res, err := postsCollection.UpdateOne(context.Background(), pollFilter, voteUpdate, arrayFilters)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to cast vote",
			})
		}
		if res.ModifiedCount == 0 {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": "You have already voted or the poll is expired",
			})
		}

		// Respond with success message
		return c.JSON(fiber.Map{
			"message": "Vote cast successfully",
		})
	}

	return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
		"error": "Unknown error",
	})
}
