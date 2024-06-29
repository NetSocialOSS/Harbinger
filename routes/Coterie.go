package routes

import (
	"context"
	"time"

	"socialflux/types"

	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

func getUsername(userCollection *mongo.Collection, id primitive.ObjectID, userIDToUsername map[primitive.ObjectID]string) (string, error) {
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

func GetAllCoterie(c *fiber.Ctx) error {
	db, ok := c.Locals("db").(*mongo.Client)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Database connection not available",
		})
	}

	coterieCollection := db.Database("SocialFlux").Collection("coterie")
	userCollection := db.Database("SocialFlux").Collection("users")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cursor, err := coterieCollection.Find(ctx, bson.M{})
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	defer cursor.Close(ctx)

	var coteries []types.Coterie
	if err := cursor.All(ctx, &coteries); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	// Create a map to store user IDs and their corresponding usernames
	userIDToUsername := make(map[primitive.ObjectID]string)

	// Create a slice to hold the final output
	var result []map[string]interface{}

	// Iterate over coteries to replace IDs with usernames
	for _, coterie := range coteries {
		// Get owner username
		ownerUsername, err := getUsername(userCollection, coterie.Owner, userIDToUsername)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
		}

		// Get member usernames
		var memberUsernames []string
		for _, memberID := range coterie.Members {
			memberObjectID, err := primitive.ObjectIDFromHex(memberID)
			if err != nil {
				memberUsernames = append(memberUsernames, "Invalid ID")
				continue
			}
			memberUsername, err := getUsername(userCollection, memberObjectID, userIDToUsername)
			if err != nil {
				memberUsernames = append(memberUsernames, "Unknown User")
				continue
			}
			memberUsernames = append(memberUsernames, memberUsername)
		}

		// Calculate total member count
		totalMemberCount := len(memberUsernames)

		// Append the final coterie structure to the result
		result = append(result, map[string]interface{}{
			"_id":          coterie.ID.Hex(),
			"name":         coterie.Name,
			"description":  coterie.Description,
			"members":      memberUsernames,
			"owner":        ownerUsername,
			"TotalMembers": totalMemberCount,
		})
	}

	return c.JSON(result)
}

// GetCoterieByName fetches the details of a specific coterie by its name.
func GetCoterieByName(c *fiber.Ctx) error {
	db, ok := c.Locals("db").(*mongo.Client)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Database connection not available",
		})
	}

	coterieCollection := db.Database("SocialFlux").Collection("coterie")
	userCollection := db.Database("SocialFlux").Collection("users")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Get the coterie name from the URL parameter
	coterieName := c.Params("name")

	// Find the coterie by its name (case-insensitive query)
	var coterie types.Coterie
	err := coterieCollection.FindOne(ctx, bson.M{"name": bson.M{"$regex": coterieName, "$options": "i"}}).Decode(&coterie)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Coterie not found"})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	// Create a map to store user IDs and their corresponding usernames
	userIDToUsername := make(map[primitive.ObjectID]string)

	// Get owner username
	ownerUsername, err := getUsername(userCollection, coterie.Owner, userIDToUsername)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	// Get member usernames
	var memberUsernames []string
	for _, memberID := range coterie.Members {
		memberObjectID, err := primitive.ObjectIDFromHex(memberID)
		if err != nil {
			memberUsernames = append(memberUsernames, "Invalid ID")
			continue
		}
		memberUsername, err := getUsername(userCollection, memberObjectID, userIDToUsername)
		if err != nil {
			memberUsernames = append(memberUsernames, "Unknown User")
			continue
		}
		memberUsernames = append(memberUsernames, memberUsername)
	}

	// Calculate total member count
	totalMemberCount := len(memberUsernames)

	// Create the final coterie structure
	result := map[string]interface{}{
		"_id":          coterie.ID.Hex(),
		"name":         coterie.Name,
		"description":  coterie.Description,
		"members":      memberUsernames,
		"owner":        ownerUsername,
		"TotalMembers": totalMemberCount,
	}

	return c.JSON(result)
}

// AddNewCoterie handles the creation of a new coterie.
func AddNewCoterie(c *fiber.Ctx) error {
	db, ok := c.Locals("db").(*mongo.Client)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Database connection not available",
		})
	}

	coterieCollection := db.Database("SocialFlux").Collection("coterie")
	usersCollection := db.Database("SocialFlux").Collection("users")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Get the title and owner from query parameters
	title := c.Query("title")
	owner := c.Query("owner")

	// Validate the owner ObjectID
	ownerObjectID, err := primitive.ObjectIDFromHex(owner)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid id of the owner",
		})
	}

	// Check if the owner exists in the users collection
	var user bson.M
	err = usersCollection.FindOne(ctx, bson.M{"_id": ownerObjectID}).Decode(&user)
	if err == mongo.ErrNoDocuments {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "Owner not found",
		})
	} else if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Error checking owner existence: " + err.Error(),
		})
	}

	// Create a new coterie instance
	newCoterie := bson.M{
		"_id":         primitive.NewObjectID(),
		"name":        title,
		"description": "",
		"members":     []string{},
		"owner":       ownerObjectID,
		"banner":      "",
		"avatar":      "",
	}

	// Insert the new coterie into the collection
	_, err = coterieCollection.InsertOne(ctx, newCoterie)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	// Prepare the response
	response := map[string]interface{}{
		"_id":         newCoterie["_id"].(primitive.ObjectID).Hex(),
		"name":        newCoterie["name"],
		"description": newCoterie["description"],
		"members":     newCoterie["members"],
		"owner":       bson.M{"$oid": newCoterie["owner"].(primitive.ObjectID).Hex()},
		"banner":      newCoterie["banner"],
		"avatar":      newCoterie["avatar"],
	}

	return c.Status(fiber.StatusCreated).JSON(response)
}

// JoinCoterie allows a user to join a coterie by its name and the user's id
func JoinCoterie(c *fiber.Ctx) error {
	db, ok := c.Locals("db").(*mongo.Client)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Database connection not available",
		})
	}

	coterieCollection := db.Database("SocialFlux").Collection("coterie")
	userCollection := db.Database("SocialFlux").Collection("users")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Get the coterie name and joiner id from the URL parameters
	coterieName := c.Query("name")
	joinerID := c.Query("userID")

	// Validate the joiner ObjectID
	joinerObjectID, err := primitive.ObjectIDFromHex(joinerID)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid user ID",
		})
	}

	// Check if the joiner exists in the users collection
	var joiner bson.M
	err = userCollection.FindOne(ctx, bson.M{"_id": joinerObjectID}).Decode(&joiner)
	if err == mongo.ErrNoDocuments {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "User not found",
		})
	} else if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Error checking users existence: " + err.Error(),
		})
	}

	// Find the coterie by its name (case-insensitive query)
	var coterie types.Coterie
	err = coterieCollection.FindOne(ctx, bson.M{"name": bson.M{"$regex": coterieName, "$options": "i"}}).Decode(&coterie)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Coterie not found"})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	// Check if the joiner is already a member of the coterie
	for _, memberID := range coterie.Members {
		if memberID == joinerID {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "User is already a member of the coterie",
			})
		}
	}

	// Add the joiner to the coterie's members list
	coterie.Members = append(coterie.Members, joinerID)

	// Update the coterie in the database
	_, err = coterieCollection.UpdateOne(
		ctx,
		bson.M{"_id": coterie.ID},
		bson.M{"$set": bson.M{"members": coterie.Members}},
	)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	// Prepare the response
	response := map[string]interface{}{
		"_id":          coterie.ID.Hex(),
		"name":         coterie.Name,
		"description":  coterie.Description,
		"members":      coterie.Members,
		"owner":        coterie.Owner.Hex(),
		"TotalMembers": len(coterie.Members),
	}

	return c.Status(fiber.StatusOK).JSON(response)
}

// LeaveCoterie allows a user to leave a coterie by its name and the user's id
func LeaveCoterie(c *fiber.Ctx) error {
	db, ok := c.Locals("db").(*mongo.Client)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Database connection not available",
		})
	}

	coterieCollection := db.Database("SocialFlux").Collection("coterie")
	userCollection := db.Database("SocialFlux").Collection("users")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Get the coterie name and leaver id from the URL parameters
	coterieName := c.Query("name")
	leaverID := c.Query("userID")

	// Validate the leaver ObjectID
	leaverObjectID, err := primitive.ObjectIDFromHex(leaverID)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid leaver ID",
		})
	}

	// Check if the leaver exists in the users collection
	var leaver bson.M
	err = userCollection.FindOne(ctx, bson.M{"_id": leaverObjectID}).Decode(&leaver)
	if err == mongo.ErrNoDocuments {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "Leaver not found",
		})
	} else if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Error checking leaver existence: " + err.Error(),
		})
	}

	// Find the coterie by its name (case-insensitive query)
	var coterie types.Coterie
	err = coterieCollection.FindOne(ctx, bson.M{"name": bson.M{"$regex": coterieName, "$options": "i"}}).Decode(&coterie)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Coterie not found"})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	// Check if the leaver is a member of the coterie
	var newMembers []string
	found := false
	for _, memberID := range coterie.Members {
		if memberID != leaverID {
			newMembers = append(newMembers, memberID)
		} else {
			found = true
		}
	}

	if !found {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Leaver is not a member of the coterie",
		})
	}

	// Update the coterie in the database
	_, err = coterieCollection.UpdateOne(
		ctx,
		bson.M{"_id": coterie.ID},
		bson.M{"$set": bson.M{"members": newMembers}},
	)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	// Prepare the response
	response := map[string]interface{}{
		"_id":          coterie.ID.Hex(),
		"name":         coterie.Name,
		"description":  coterie.Description,
		"members":      newMembers,
		"owner":        coterie.Owner.Hex(),
		"TotalMembers": len(newMembers),
	}

	return c.Status(fiber.StatusOK).JSON(response)
}

func CoterieRoutes(app *fiber.App) {
	app.Get("/coterie/@all", GetAllCoterie)
	app.Post("/coterie/leave", LeaveCoterie)
	app.Get("/coterie/:name", GetCoterieByName)
	app.Post("/coterie/join", JoinCoterie)
	app.Post("/coterie/new", AddNewCoterie)
}
