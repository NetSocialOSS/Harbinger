package routes

import (
	"context"

	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// FollowUser allows one user to follow another
func FollowUser(c *fiber.Ctx) error {
	db, ok := c.Locals("db").(*mongo.Client)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database connection not available"})
	}

	username := c.Params("username")
	followerID := c.Params("followerID")

	userCollection := db.Database("SocialFlux").Collection("users")

	// Find the user to be followed
	var userToBeFollowed bson.M
	err := userCollection.FindOne(context.TODO(), bson.M{"username": username}).Decode(&userToBeFollowed)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "User not found"})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Error finding user"})
	}

	// Find the follower user
	var followerUser bson.M
	followerObjectID, err := primitive.ObjectIDFromHex(followerID)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid follower ID"})
	}

	err = userCollection.FindOne(context.TODO(), bson.M{"_id": followerObjectID}).Decode(&followerUser)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Follower not found"})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Error finding follower"})
	}

	// Add follower's user ID to the user's followers list
	followedUserFilter := bson.M{"username": username}
	followedUserUpdate := bson.M{"$addToSet": bson.M{"followers": followerID}}
	_, err = userCollection.UpdateOne(context.TODO(), followedUserFilter, followedUserUpdate, options.Update().SetUpsert(false))
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Error updating followers list"})
	}

	// Add followed user's ID to the follower's following list
	followerUserFilter := bson.M{"_id": followerObjectID}
	followerUserUpdate := bson.M{"$addToSet": bson.M{"following": userToBeFollowed["_id"].(primitive.ObjectID).Hex()}}
	_, err = userCollection.UpdateOne(context.TODO(), followerUserFilter, followerUserUpdate, options.Update().SetUpsert(false))
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Error updating following list"})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{"message": "Successfully followed user"})
}

func UnfollowUser(c *fiber.Ctx) error {
	db, ok := c.Locals("db").(*mongo.Client)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database connection not available"})
	}

	username := c.Params("username")
	followerID := c.Params("followerID")

	userCollection := db.Database("SocialFlux").Collection("users")

	// Find the user to be unfollowed
	var user bson.M
	err := userCollection.FindOne(context.TODO(), bson.M{"username": username}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "User not found"})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Error finding user"})
	}

	// Remove follower's user ID from the user's followers list
	filter := bson.M{"username": username}
	update := bson.M{"$pull": bson.M{"followers": followerID}}
	_, err = userCollection.UpdateOne(context.TODO(), filter, update, options.Update().SetUpsert(false))
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Error updating followers list"})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{"message": "Successfully unfollowed user"})
}
