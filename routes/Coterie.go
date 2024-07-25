package routes

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"netsocial/types"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
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

		coterieMap := map[string]interface{}{
			"name":         coterie.Name,
			"description":  coterie.Description,
			"createdAt":    coterie.CreatedAt,
			"owner":        ownerUsername,
			"TotalMembers": len(memberUsernames),
			"PostsCount":   postCount,
		}

		if coterie.Avatar != "" {
			coterieMap["avatar"] = coterie.Avatar
		}

		if coterie.Banner != "" {
			coterieMap["banner"] = coterie.Banner
		}

		result = append(result, coterieMap)
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

	// Fetch owner username
	ownerUsername, err := getUsername(userCollection, coterie.Owner, userIDToUsername)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	// Fetch member usernames
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

	// Fetch role usernames
	roleUsernames := make(map[string][]string)
	for role, ids := range coterie.Roles {
		var usernames []string
		for _, id := range ids {
			objectID, err := primitive.ObjectIDFromHex(id)
			if err != nil {
				usernames = append(usernames, "Invalid ID")
				continue
			}
			username, err := getUsername(userCollection, objectID, userIDToUsername)
			if err != nil {
				usernames = append(usernames, "Unknown User")
				continue
			}
			usernames = append(usernames, username)
		}
		roleUsernames[role] = usernames
	}

	// Fetch total post count
	postCount, err := postsCollection.CountDocuments(ctx, bson.M{"coterie": coterie.Name})
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	// Fetch posts
	postCursor, err := postsCollection.Find(ctx, bson.M{"coterie": coterie.Name})
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	defer postCursor.Close(ctx)

	var posts []map[string]interface{}
	for postCursor.Next(ctx) {
		var post types.Post
		if err := postCursor.Decode(&post); err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
		}

		// Replace author ID with username
		var author types.User
		err := userCollection.FindOne(ctx, bson.M{"_id": post.Author}).Decode(&author)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
		}

		// Replace hearts IDs with usernames
		var heartsUsernames []string
		for _, heartID := range post.Hearts {
			heartObjectID, err := primitive.ObjectIDFromHex(heartID)
			if err != nil {
				heartsUsernames = append(heartsUsernames, "Invalid ID")
				continue
			}
			heartUsername, err := getUsername(userCollection, heartObjectID, userIDToUsername)
			if err != nil {
				heartsUsernames = append(heartsUsernames, "Unknown User")
				continue
			}
			heartsUsernames = append(heartsUsernames, heartUsername)
		}

		postMap := map[string]interface{}{
			"_id":       post.ID,
			"title":     post.Title,
			"content":   post.Content,
			"hearts":    heartsUsernames,
			"createdAt": post.CreatedAt,
			"coterie":   post.Coterie,
			"author": map[string]interface{}{
				"isVerified":     author.IsVerified,
				"isOrganisation": author.IsOrganisation,
				"isDeveloper":    author.IsDeveloper,
				"isPartner":      author.IsPartner,
				"isOwner":        author.IsOwner,
				"username":       author.Username,
			},
		}
		posts = append(posts, postMap)
	}

	// Populate coterie object with fetched data
	coterie.OwnerUsername = ownerUsername
	coterie.MemberUsernames = memberUsernames
	coterie.TotalPosts = int(postCount)

	// Prepare final result
	result := map[string]interface{}{
		"name":         coterie.Name,
		"description":  coterie.Description,
		"WarningLimit": coterie.WarningLimit,
		"members":      memberUsernames,
		"owner":        ownerUsername,
		"createdAt":    coterie.CreatedAt,
		"TotalMembers": len(memberUsernames),
		"roles":        roleUsernames,
		"Post":         posts,
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

	// Get the name and owner from query parameters
	title := c.Query("name")
	owner := c.Query("owner")

	// Check if the title is blank
	if title == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Coterie name cannot be blank",
		})
	}

	// Validate the owner ObjectID
	ownerObjectID, err := primitive.ObjectIDFromHex(owner)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid id of the owner",
		})
	}

	// Check if the owner exists in the users collection
	var user types.User
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

	// Check if the owner is banned
	if user.IsBanned {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error": "Hey there, you are banned from using NetSocial's services.",
		})
	}

	// Check if a coterie with an exact name already exists
	var existingCoterie types.Coterie
	err = coterieCollection.FindOne(ctx, bson.M{"name": title}).Decode(&existingCoterie)
	if err == nil {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{
			"error": "A coterie with this name already exists",
		})
	} else if err != mongo.ErrNoDocuments {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Error checking coterie name: " + err.Error(),
		})
	}

	// Create a new coterie instance with the CreatedAt field
	newCoterie := bson.M{
		"_id":         primitive.NewObjectID(),
		"name":        title,
		"description": "",
		"members":     []primitive.ObjectID{ownerObjectID},
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
		"members":     []string{newCoterie["owner"].(primitive.ObjectID).Hex()},
		"owner":       bson.M{"$oid": newCoterie["owner"].(primitive.ObjectID).Hex()},
		"banner":      newCoterie["banner"],
		"avatar":      newCoterie["avatar"],
		"createdAt":   newCoterie["createdAt"],
	}

	return c.Status(fiber.StatusCreated).JSON(response)
}

// JoinCoterie allows a user to join a coterie by its name and the user's ID
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
	var joiner types.User
	err = userCollection.FindOne(ctx, bson.M{"_id": joinerObjectID}).Decode(&joiner)
	if err == mongo.ErrNoDocuments {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "User not found",
		})
	} else if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Error checking user's existence: " + err.Error(),
		})
	}

	// Check if the user is banned
	if joiner.IsBanned {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error": "Hey there, you are banned from using NetSocial's services.",
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

	// Check if the joiner is in the banned members list
	for _, bannedID := range coterie.BannedMembers {
		if bannedID == joinerID {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": "You are banned from joining this coterie",
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
		"message":      fmt.Sprintf("You have successfully joined '%s'", coterie.Name),
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
		"_id":         coterie.ID.Hex(),
		"name":        coterie.Name,
		"description": coterie.Description,
		"message":     fmt.Sprintf("You have successfully left '%s'", coterie.Name),
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

func UpdateCoterie(c *fiber.Ctx) error {
	db, ok := c.Locals("db").(*mongo.Client)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Database connection not available",
		})
	}
	coterieCollection := db.Database("SocialFlux").Collection("coterie")

	// Parse query parameters
	newName := c.Query("newName")
	newDescription := c.Query("newDescription")
	ownerID := c.Query("ownerID")

	// Validate owner ID
	ownerObjectID, err := primitive.ObjectIDFromHex(ownerID)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid owner ID",
		})
	}

	// Check if the owner ID matches the coterie owner
	coterieName := c.Query("name")
	filter := bson.M{"name": coterieName, "owner": ownerObjectID}

	updateFields := bson.M{}
	if newName != "" {
		updateFields["name"] = newName
	}
	if newDescription != "" {
		updateFields["description"] = newDescription
	}

	update := bson.M{"$set": updateFields}

	// Perform the update operation
	result, err := coterieCollection.UpdateOne(context.Background(), filter, update)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to update coterie",
		})
	}

	if result.ModifiedCount == 0 {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "Coterie not found or you are not the owner",
		})
	}

	// Respond with success message
	response := fiber.Map{
		"message": "Coterie updated successfully",
		"updates": updateFields,
	}

	return c.JSON(response)
}

func WarnMember(c *fiber.Ctx) error {
	db, ok := c.Locals("db").(*mongo.Client)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database connection not available"})
	}

	coterieCollection := db.Database("SocialFlux").Collection("coterie")
	userCollection := db.Database("SocialFlux").Collection("users")

	name := c.Query("name")
	membername := c.Query("membername")
	modIDStr := c.Query("modID")
	reason := c.Query("reason")

	if name == "" || membername == "" || modIDStr == "" || reason == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "All query parameters are required"})
	}

	modID, err := primitive.ObjectIDFromHex(modIDStr)
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Invalid modID format"})
	}

	var member bson.M
	err = userCollection.FindOne(context.TODO(), bson.M{"username": membername}).Decode(&member)
	if err != nil {
		return c.Status(http.StatusNotFound).JSON(fiber.Map{"error": "Member not found"})
	}

	var mod bson.M
	err = userCollection.FindOne(context.TODO(), bson.M{"_id": modID}).Decode(&mod)
	if err != nil {
		return c.Status(http.StatusNotFound).JSON(fiber.Map{"error": "Mod not found"})
	}

	memberID := member["_id"].(primitive.ObjectID).Hex()

	// Fetch coterie and check if modID is authorized
	var coterie types.Coterie
	err = coterieCollection.FindOne(context.TODO(), bson.M{"name": name}).Decode(&coterie)
	if err != nil {
		return c.Status(http.StatusNotFound).JSON(fiber.Map{"error": "Coterie not found"})
	}

	// Check if the member is in the coterie's member list
	isMember := false
	for _, memberIDInCoterie := range coterie.Members {
		if memberIDInCoterie == memberID {
			isMember = true
			break
		}
	}

	if !isMember {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "The user is not a member of the coterie"})
	}

	isAuthorized := false
	for _, owner := range coterie.Roles["owners"] {
		if owner == modIDStr {
			isAuthorized = true
			break
		}
	}
	if !isAuthorized {
		for _, admin := range coterie.Roles["admins"] {
			if admin == modIDStr {
				isAuthorized = true
				break
			}
		}
	}
	if !isAuthorized {
		for _, moderator := range coterie.Roles["moderators"] {
			if moderator == modIDStr {
				isAuthorized = true
				break
			}
		}
	}

	if !isAuthorized {
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized. Only owners, admins, or moderators can warn members."})
	}

	// Update warning details in the coterie
	filter := bson.M{"name": name, "owner": coterie.Owner}
	update := bson.M{
		"$push": bson.M{
			"warningDetails." + memberID: bson.M{
				"reason": reason,
				"time":   time.Now(),
			},
		},
	}

	opts := options.FindOneAndUpdate().SetReturnDocument(options.After)
	var updatedCoterie types.Coterie
	err = coterieCollection.FindOneAndUpdate(context.TODO(), filter, update, opts).Decode(&updatedCoterie)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update coterie"})
	}

	// Check if member has exceeded warning limit
	if len(updatedCoterie.WarningDetails[memberID]) > updatedCoterie.WarningLimit {
		// Remove member from the members list
		filter := bson.M{"name": name, "owner": coterie.Owner}
		update := bson.M{
			"$pull": bson.M{"members": memberID},
		}

		opts := options.Update().SetUpsert(false)
		_, err := coterieCollection.UpdateOne(context.TODO(), filter, update, opts)
		if err != nil {
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to remove member"})
		}

		// Remove member's warning details
		updateWarning := bson.M{
			"$unset": bson.M{"warningDetails." + memberID: ""},
		}

		_, err = coterieCollection.UpdateOne(context.TODO(), filter, updateWarning, opts)
		if err != nil {
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to remove member's warning details"})
		}

		// Return response with removal message
		return c.Status(http.StatusOK).JSON(fiber.Map{"message": fmt.Sprintf("User removed because they reached the warning limit %d", updatedCoterie.WarningLimit)})
	}

	// Return success response if member warning was added without reaching limit
	return c.Status(http.StatusOK).JSON(fiber.Map{
		"message": fmt.Sprintf("Member %s is successfully warned for reason: %s", membername, reason),
	})
}

func promoteMember(c *fiber.Ctx) error {
	// Connect to MongoDB
	db, ok := c.Locals("db").(*mongo.Client)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Database connection not available",
		})
	}

	coterieCollection := db.Database("SocialFlux").Collection("coterie")
	userCollection := db.Database("SocialFlux").Collection("users")

	// Parse and validate parameters from request body or query
	coterieName := c.FormValue("CoterieName")
	role := c.FormValue("role")
	memberName := c.FormValue("MemberName")
	promoterIDStr := c.FormValue("PromoterID")

	// Convert promoterIDStr to ObjectID
	promoterID, err := primitive.ObjectIDFromHex(promoterIDStr)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid PromoterID",
		})
	}

	// Find the member's ObjectID in users collection
	var member struct {
		ID primitive.ObjectID `bson:"_id"`
	}
	err = userCollection.FindOne(context.TODO(), bson.M{"username": memberName}).Decode(&member)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "Member not found",
		})
	}

	// Update coterie document based on role
	filter := bson.M{"name": coterieName}
	update := bson.M{}

	switch role {
	case "Admin":
		update = bson.M{"$push": bson.M{"roles.admins": member.ID.Hex()}}
	case "Moderator":
		update = bson.M{"$push": bson.M{"roles.moderators": member.ID.Hex()}}
	case "Owner":
		// Only the current owner can promote a new owner
		var coterie types.Coterie
		err := coterieCollection.FindOne(context.TODO(), filter).Decode(&coterie)
		if err != nil {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error": "Coterie not found",
			})
		}
		if coterie.Owner != promoterID {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Only the current owner can promote a new owner",
			})
		}
		update = bson.M{
			"$push": bson.M{"roles.owners": member.ID.Hex()},
		}
	default:
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid role specified",
		})
	}

	// Perform the update in MongoDB
	_, err = coterieCollection.UpdateOne(context.TODO(), filter, update)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to update coterie",
		})
	}

	return c.JSON(fiber.Map{
		"message": fmt.Sprintf("Successfully promoted %s to %s in coterie %s", memberName, role, coterieName),
	})
}

// BanUser handles banning a user from a coterie
func BanUser(c *fiber.Ctx) error {
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

	// Parse query parameters
	coterieName := c.Query("name")
	username := c.Query("username")
	modID := c.Query("modID")

	// Fetch moderator details
	var moderator types.User
	moderatorObjectID, err := primitive.ObjectIDFromHex(modID)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid moderator ID",
		})
	}
	err = userCollection.FindOne(ctx, bson.M{"_id": moderatorObjectID}).Decode(&moderator)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error": "Moderator not found",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Error fetching moderator: " + err.Error(),
		})
	}

	// Fetch coterie details
	var coterie types.Coterie
	err = coterieCollection.FindOne(ctx, bson.M{"name": coterieName}).Decode(&coterie)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error": "Coterie not found",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Error fetching coterie: " + err.Error(),
		})
	}

	// Fetch user details
	var user types.User
	err = userCollection.FindOne(ctx, bson.M{"username": username}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error": "User not found",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Error fetching user: " + err.Error(),
		})
	}

	// Check if user is a member of the coterie
	var isMember bool
	for _, memberID := range coterie.Members {
		if memberID == user.ID.Hex() {
			isMember = true
			break
		}
	}
	if !isMember {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "User is not a member of this coterie",
		})
	}

	// Add user to bannedMembers array in coterie document
	update := bson.M{
		"$push": bson.M{
			"bannedMembers": user.ID.Hex(),
		},
	}
	_, err = coterieCollection.UpdateOne(ctx, bson.M{"_id": coterie.ID}, update)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Error updating coterie: " + err.Error(),
		})
	}

	// Mark user as banned in users collection
	updateUser := bson.M{
		"$set": bson.M{
			"isBanned": true,
		},
	}
	_, err = userCollection.UpdateOne(ctx, bson.M{"_id": user.ID}, updateUser)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Error updating user: " + err.Error(),
		})
	}

	// Return success response
	return c.JSON(fiber.Map{
		"message": fmt.Sprintf("User '%s' has been banned from coterie '%s' by moderator '%s'", username, coterieName, moderator.Username),
	})
}

// Rate limit configuration
var rateLimitConfig = limiter.Config{
	Max:        5,             // Maximum number of requests
	Expiration: 60 * 1000 * 2, // 2 minutes
	LimitReached: func(c *fiber.Ctx) error {
		return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
			"error": "Woah! Slow down bucko! You're being rate limited!",
		})
	},
}

func CoterieRoutes(app *fiber.App) {
	app.Get("/coterie/@all", GetAllCoterie)
	app.Post("/coterie/leave", limiter.New(rateLimitConfig), LeaveCoterie)
	app.Post("/coterie/set-warning-limit", limiter.New(rateLimitConfig), SetWarningLimit)
	app.Get("/coterie/:name", GetCoterieByName)
	app.Post("/coterie/update", limiter.New(rateLimitConfig), UpdateCoterie)
	app.Post("/coterie/join", limiter.New(rateLimitConfig), JoinCoterie)
	app.Post("/coterie/promote", limiter.New(rateLimitConfig), promoteMember)
	app.Post("/coterie/ban", limiter.New(rateLimitConfig), BanUser)
	app.Post("/coterie/warn", limiter.New(rateLimitConfig), WarnMember)
	app.Post("/coterie/new", limiter.New(rateLimitConfig), AddNewCoterie)
}
