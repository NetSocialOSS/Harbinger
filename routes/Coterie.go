package routes

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"netsocial/types"

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
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database connection not available"})
	}

	coterieCollection := db.Database("SocialFlux").Collection("coterie")
	userCollection := db.Database("SocialFlux").Collection("users")
	postCollection := db.Database("SocialFlux").Collection("posts")

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

	userIDToUsername := make(map[primitive.ObjectID]string)
	var result []map[string]interface{}

	for _, coterie := range coteries {
		ownerUsername, err := getUsername(userCollection, coterie.Owner, userIDToUsername)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
		}

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

		// Fetch and count posts for this coterie
		postCount, err := postCollection.CountDocuments(ctx, bson.M{"coterie": coterie.Name})
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
		}

		totalMemberCount := len(memberUsernames)
		result = append(result, map[string]interface{}{
			"_id":          coterie.ID.Hex(),
			"name":         coterie.Name,
			"description":  coterie.Description,
			"createdAt":    coterie.CreatedAt,
			"members":      memberUsernames,
			"owner":        ownerUsername,
			"TotalMembers": totalMemberCount,
			"PostsCount":   postCount,     // Adding the posts count
			"roles":        coterie.Roles, // Return roles
		})
	}

	return c.JSON(result)
}

func GetCoterieByName(c *fiber.Ctx) error {
	db, ok := c.Locals("db").(*mongo.Client)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database connection not available"})
	}

	coterieCollection := db.Database("SocialFlux").Collection("coterie")
	userCollection := db.Database("SocialFlux").Collection("users")
	postsCollection := db.Database("SocialFlux").Collection("posts")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	coterieName := c.Params("name")

	var coterie types.Coterie
	err := coterieCollection.FindOne(ctx, bson.M{"name": bson.M{"$regex": coterieName, "$options": "i"}}).Decode(&coterie)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Coterie not found"})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	userIDToUsername := make(map[primitive.ObjectID]string)

	ownerUsername, err := getUsername(userCollection, coterie.Owner, userIDToUsername)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

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

	// Fetch and count posts for this coterie
	postCount, err := postsCollection.CountDocuments(ctx, bson.M{"coterie": coterie.Name})
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	coterie.OwnerUsername = ownerUsername
	coterie.MemberUsernames = memberUsernames
	coterie.TotalPosts = int(postCount)

	// Return roles as well
	result := map[string]interface{}{
		"coterie": coterie,
		"roles":   coterie.Roles,
	}

	return c.Status(fiber.StatusOK).JSON(result)
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

	// Create a new coterie instance with the CreatedAt field
	newCoterie := bson.M{
		"_id":         primitive.NewObjectID(),
		"name":        title,
		"description": "",
		"members":     []string{},
		"owner":       ownerObjectID,
		"banner":      "",
		"avatar":      "",
		"createdAt":   time.Now(),
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
		"createdAt":   newCoterie["createdAt"],
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

func SetWarningLimit(c *fiber.Ctx) error {
	db, ok := c.Locals("db").(*mongo.Client)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Database connection not available",
		})
	}
	coterieCollection := db.Database("SocialFlux").Collection("coterie")

	// Parse request parameters
	name := c.Query("name")
	limitStr := c.Query("limitnumber")
	ownerIDStr := c.Query("OwnerID")

	// Validate and convert parameters
	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit < 1 || limit > 9 {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid warning limit. Must be between 1 and 9.",
		})
	}

	ownerID, err := primitive.ObjectIDFromHex(ownerIDStr)
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid OwnerID.",
		})
	}

	// Check if the owner ID in the URL matches the owner ID in the coterie document
	var coterie types.Coterie
	err = coterieCollection.FindOne(context.Background(), bson.M{"name": name}).Decode(&coterie)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "Coterie not found.",
		})
	}

	if coterie.Owner != ownerID {
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{
			"error": "Unauthorized. Only the coterie owner can update the warning limit.",
		})
	}

	// Update warning limit in database
	filter := bson.M{"name": name, "owner": ownerID}
	update := bson.M{"$set": bson.M{"warningLimit": limit}}

	_, err = coterieCollection.UpdateOne(context.Background(), filter, update)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to update warning limit.",
		})
	}

	// Respond with success message
	return c.JSON(fiber.Map{
		"message":      "Warning limit updated",
		"warningLimit": limit,
	})
}

func UpdateCoterieName(c *fiber.Ctx) error {
	db, ok := c.Locals("db").(*mongo.Client)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Database connection not available",
		})
	}
	coterieCollection := db.Database("SocialFlux").Collection("coterie")

	// Parse request parameters
	name := c.Query("name")
	newName := c.Query("newname")
	ownerIDStr := c.Query("ownerID")

	// Validate owner ID
	ownerID, err := primitive.ObjectIDFromHex(ownerIDStr)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid owner ID",
		})
	}

	// Check if the owner ID matches the coterie owner
	filter := bson.M{"name": name, "owner": ownerID}
	update := bson.M{"$set": bson.M{"name": newName}}

	// Perform the update operation
	result, err := coterieCollection.UpdateOne(context.Background(), filter, update)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to update coterie name",
		})
	}

	if result.ModifiedCount == 0 {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "Coterie not found or you are not the owner",
		})
	}

	// Respond with success message
	return c.JSON(fiber.Map{
		"message": "Coterie name updated successfully",
		"oldName": name,
		"newName": newName,
	})
}

func CoterieRoutes(app *fiber.App) {
	app.Get("/coterie/@all", GetAllCoterie)
	app.Post("/coterie/leave", LeaveCoterie)
	app.Post("/coterie/set-warning-limit", SetWarningLimit)
	app.Get("/coterie/:name", GetCoterieByName)
	app.Post("/coterie/update-name", UpdateCoterieName)
	app.Post("/coterie/join", JoinCoterie)
	app.Post("/coterie/new", AddNewCoterie)
}
