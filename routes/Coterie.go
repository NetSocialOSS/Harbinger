package routes

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"netsocial/middlewares"
	"netsocial/types"
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

func GetAllCoterie(w http.ResponseWriter, r *http.Request) {
	db := r.Context().Value("db").(*mongo.Client)

	coterieCollection := db.Database("SocialFlux").Collection("coterie")
	userCollection := db.Database("SocialFlux").Collection("users")
	postCollection := db.Database("SocialFlux").Collection("posts")

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	cursor, err := coterieCollection.Find(ctx, bson.M{})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer cursor.Close(ctx)

	var coteries []types.Coterie
	if err := cursor.All(ctx, &coteries); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	userIDToUsername := make(map[primitive.ObjectID]string)
	var result []map[string]interface{}

	for _, coterie := range coteries {
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

		postCount, err := postCollection.CountDocuments(ctx, bson.M{"coterie": coterie.Name})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		coterieMap := map[string]interface{}{
			"name":           coterie.Name,
			"description":    coterie.Description,
			"createdAt":      coterie.CreatedAt,
			"isVerified":     coterie.IsVerified,
			"isOrganisation": coterie.IsOrganisation,
			"TotalMembers":   len(memberUsernames),
			"PostsCount":     postCount,
		}

		if coterie.Avatar != "" {
			coterieMap["avatar"] = coterie.Avatar
		}

		if coterie.Banner != "" {
			coterieMap["banner"] = coterie.Banner
		}

		result = append(result, coterieMap)
	}

	json.NewEncoder(w).Encode(result)
}

func GetCoterieByName(w http.ResponseWriter, r *http.Request) {
	db := r.Context().Value("db").(*mongo.Client)

	coterieCollection := db.Database("SocialFlux").Collection("coterie")
	userCollection := db.Database("SocialFlux").Collection("users")
	postsCollection := db.Database("SocialFlux").Collection("posts")
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	coterieName := chi.URLParam(r, "name")

	var coterie types.Coterie
	err := coterieCollection.FindOne(ctx, bson.M{"name": bson.M{"$regex": coterieName, "$options": "i"}}).Decode(&coterie)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			http.Error(w, "Coterie not found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	userIDToDetails := make(map[primitive.ObjectID]map[string]string)

	ownerDetails, err := getUserDetails(userCollection, coterie.Owner, userIDToDetails)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var memberDetails []map[string]interface{}
	for _, memberID := range coterie.Members {
		memberObjectID, err := primitive.ObjectIDFromHex(memberID)
		if err != nil {
			memberDetails = append(memberDetails, map[string]interface{}{
				"username":       "Invalid ID",
				"profilePicture": "",
			})
			continue
		}
		details, err := getUserDetails(userCollection, memberObjectID, userIDToDetails)
		if err != nil {
			memberDetails = append(memberDetails, map[string]interface{}{
				"username":       "Unknown User",
				"profilePicture": "",
			})
			continue
		}
		memberDetails = append(memberDetails, details)
	}

	postCount, err := postsCollection.CountDocuments(ctx, bson.M{"coterie": coterie.Name})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	postCursor, err := postsCollection.Find(ctx, bson.M{"coterie": coterie.Name}, options.Find().SetSort(bson.D{{Key: "createdAt", Value: -1}}))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer postCursor.Close(ctx)

	var posts []map[string]interface{}
	for postCursor.Next(ctx) {
		var post types.Post
		if err := postCursor.Decode(&post); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		var author types.User
		err := userCollection.FindOne(ctx, bson.M{"_id": post.Author}).Decode(&author)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		var heartsDetails []map[string]interface{}
		for _, heartID := range post.Hearts {
			heartObjectID, err := primitive.ObjectIDFromHex(heartID)
			if err != nil {
				heartsDetails = append(heartsDetails, map[string]interface{}{
					"username": "Invalid ID",
				})
				continue
			}
			details, err := getUserDetails(userCollection, heartObjectID, userIDToDetails)
			if err != nil {
				heartsDetails = append(heartsDetails, map[string]interface{}{
					"username": "Unknown User",
				})
				continue
			}
			heartsDetails = append(heartsDetails, details)
		}

		if post.Poll != nil {
			totalVotes := 0
			for i := range post.Poll {
				for j := range post.Poll[i].Options {
					optionVoteCount := len(post.Poll[i].Options[j].Votes)
					totalVotes += optionVoteCount

					post.Poll[i].Options[j].Votes = nil
					post.Poll[i].Options[j].VoteCount = optionVoteCount
				}
			}
			if len(post.Poll) > 0 {
				post.Poll[0].TotalVotes = totalVotes
			}
		}

		now := time.Now()

		if !post.ScheduledFor.IsZero() {
			if post.ScheduledFor.After(now) {
				continue
			}
		}

		postMap := map[string]interface{}{
			"_id":           post.ID,
			"title":         post.Title,
			"content":       post.Content,
			"image":         post.Image,
			"hearts":        heartsDetails,
			"poll":          post.Poll,
			"timeAgo":       calculateTimeAgo(post.CreatedAt),
			"commentNumber": len(post.Comments),
			"authorDetails": map[string]interface{}{
				"isVerified":     author.IsVerified,
				"isOrganisation": author.IsOrganisation,
				"isDeveloper":    author.IsDeveloper,
				"profileBanner":  author.ProfileBanner,
				"profilePicture": author.ProfilePicture,
				"isPartner":      author.IsPartner,
				"isOwner":        author.IsOwner,
				"isModerator":    author.IsModerator,
				"username":       author.Username},
		}
		if !post.ScheduledFor.IsZero() {
			postMap["scheduledFor"] = post.ScheduledFor
		}
		posts = append(posts, postMap)
	}

	coterie.OwnerUsername = ownerDetails["username"].(string)
	coterie.MemberDetails = memberDetails
	coterie.TotalPosts = int(postCount)

	result := map[string]interface{}{
		"name":           coterie.Name,
		"description":    coterie.Description,
		"members":        memberDetails,
		"owner":          ownerDetails,
		"isVerified":     coterie.IsVerified,
		"isOrganisation": coterie.IsOrganisation,
		"TotalPosts":     len(posts),
		"createdAt":      coterie.CreatedAt,
		"TotalMembers":   len(memberDetails),
		"Post":           posts,
	}

	if coterie.Avatar != "" {
		result["avatar"] = coterie.Avatar
	}

	if coterie.Banner != "" {
		result["banner"] = coterie.Banner
	}

	json.NewEncoder(w).Encode(result)
}

func getUserDetails(userCollection *mongo.Collection, userID primitive.ObjectID, cache map[primitive.ObjectID]map[string]string) (map[string]interface{}, error) {
	if userDetails, ok := cache[userID]; ok {
		return map[string]interface{}{
			"username":       userDetails["username"],
			"profilePicture": userDetails["profilePicture"],
		}, nil
	}

	var user types.User
	err := userCollection.FindOne(context.TODO(), bson.M{"_id": userID}).Decode(&user)
	if err != nil {
		return nil, err
	}

	cache[userID] = map[string]string{
		"username":       user.Username,
		"profilePicture": user.ProfilePicture,
	}

	return map[string]interface{}{
		"username":       user.Username,
		"profilePicture": user.ProfilePicture,
	}, nil
}

func AddNewCoterie(w http.ResponseWriter, r *http.Request) {
	db := r.Context().Value("db").(*mongo.Client)

	coterieCollection := db.Database("SocialFlux").Collection("coterie")
	usersCollection := db.Database("SocialFlux").Collection("users")
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	title := r.URL.Query().Get("name")
	owner := r.URL.Query().Get("owner")

	if title == "" {
		http.Error(w, "Coterie name cannot be blank", http.StatusBadRequest)
		return
	}

	ownerObjectID, err := primitive.ObjectIDFromHex(owner)
	if err != nil {
		http.Error(w, "Invalid id of the owner", http.StatusBadRequest)
		return
	}

	var user types.User
	err = usersCollection.FindOne(ctx, bson.M{"_id": ownerObjectID}).Decode(&user)
	if err == mongo.ErrNoDocuments {
		http.Error(w, "Owner not found", http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, "Error checking owner existence: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if user.IsBanned {
		http.Error(w, "Hey there, you are banned from using NetSocial's services.", http.StatusForbidden)
		return
	}

	var existingCoterie types.Coterie
	err = coterieCollection.FindOne(ctx, bson.M{"name": title}).Decode(&existingCoterie)
	if err == nil {
		http.Error(w, "A coterie with this name already exists", http.StatusConflict)
		return
	} else if err != mongo.ErrNoDocuments {
		http.Error(w, "Error checking coterie name: "+err.Error(), http.StatusInternalServerError)
		return
	}

	newCoterie := bson.M{
		"_id":         primitive.NewObjectID(),
		"name":        title,
		"description": "",
		"members":     []string{ownerObjectID.Hex()},
		"owner":       ownerObjectID,
		"banner":      "",
		"avatar":      "",
		"createdAt":   time.Now(),
	}

	_, err = coterieCollection.InsertOne(ctx, newCoterie)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

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

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

func JoinCoterie(w http.ResponseWriter, r *http.Request) {
	db := r.Context().Value("db").(*mongo.Client)

	coterieCollection := db.Database("SocialFlux").Collection("coterie")
	userCollection := db.Database("SocialFlux").Collection("users")
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	coterieName := r.URL.Query().Get("name")
	joinerID := r.URL.Query().Get("userID")

	joinerObjectID, err := primitive.ObjectIDFromHex(joinerID)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	var joiner types.User
	err = userCollection.FindOne(ctx, bson.M{"_id": joinerObjectID}).Decode(&joiner)
	if err == mongo.ErrNoDocuments {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, "Error checking user's existence: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if joiner.IsBanned {
		http.Error(w, "Hey there, you are banned from using NetSocial's services.", http.StatusForbidden)
		return
	}

	var coterie types.Coterie
	err = coterieCollection.FindOne(ctx, bson.M{"name": bson.M{"$regex": coterieName, "$options": "i"}}).Decode(&coterie)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			http.Error(w, "Coterie not found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	for _, memberID := range coterie.Members {
		if memberID == joinerID {
			http.Error(w, "User is already a member of the coterie", http.StatusBadRequest)
			return
		}
	}

	for _, bannedID := range coterie.BannedMembers {
		if bannedID == joinerID {
			http.Error(w, "You are banned from joining this coterie", http.StatusForbidden)
			return
		}
	}

	coterie.Members = append(coterie.Members, joinerID)

	_, err = coterieCollection.UpdateOne(
		ctx,
		bson.M{"_id": coterie.ID},
		bson.M{"$set": bson.M{"members": coterie.Members}},
	)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"_id":          coterie.ID.Hex(),
		"name":         coterie.Name,
		"description":  coterie.Description,
		"message":      fmt.Sprintf("You have successfully joined '%s'", coterie.Name),
		"TotalMembers": len(coterie.Members),
	}

	json.NewEncoder(w).Encode(response)
}

func LeaveCoterie(w http.ResponseWriter, r *http.Request) {
	db := r.Context().Value("db").(*mongo.Client)

	coterieCollection := db.Database("SocialFlux").Collection("coterie")
	userCollection := db.Database("SocialFlux").Collection("users")
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	coterieName := r.URL.Query().Get("name")
	leaverID := r.URL.Query().Get("userID")

	leaverObjectID, err := primitive.ObjectIDFromHex(leaverID)
	if err != nil {
		http.Error(w, "Invalid leaver ID", http.StatusBadRequest)
		return
	}

	var leaver bson.M
	err = userCollection.FindOne(ctx, bson.M{"_id": leaverObjectID}).Decode(&leaver)
	if err == mongo.ErrNoDocuments {
		http.Error(w, "Leaver not found", http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, "Error checking leaver existence: "+err.Error(), http.StatusInternalServerError)
		return
	}

	var coterie types.Coterie
	err = coterieCollection.FindOne(ctx, bson.M{"name": bson.M{"$regex": coterieName, "$options": "i"}}).Decode(&coterie)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			http.Error(w, "Coterie not found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

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
		http.Error(w, "Leaver is not a member of the coterie", http.StatusBadRequest)
		return
	}

	_, err = coterieCollection.UpdateOne(
		ctx,
		bson.M{"_id": coterie.ID},
		bson.M{"$set": bson.M{"members": newMembers}},
	)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"_id":         coterie.ID.Hex(),
		"name":        coterie.Name,
		"description": coterie.Description,
		"message":     fmt.Sprintf("You have successfully left '%s'", coterie.Name),
	}

	json.NewEncoder(w).Encode(response)
}

func SetWarningLimit(w http.ResponseWriter, r *http.Request) {
	db := r.Context().Value("db").(*mongo.Client)
	coterieCollection := db.Database("SocialFlux").Collection("coterie")

	name := r.URL.Query().Get("name")
	limitStr := r.URL.Query().Get("limitnumber")
	ownerIDStr := r.URL.Query().Get("OwnerID")

	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit < 1 || limit > 9 {
		http.Error(w, "Invalid warning limit. Must be between 1 and 9.", http.StatusBadRequest)
		return
	}

	ownerID, err := primitive.ObjectIDFromHex(ownerIDStr)
	if err != nil {
		http.Error(w, "Invalid OwnerID.", http.StatusBadRequest)
		return
	}

	var coterie types.Coterie
	err = coterieCollection.FindOne(context.Background(), bson.M{"name": name}).Decode(&coterie)
	if err != nil {
		http.Error(w, "Coterie not found.", http.StatusInternalServerError)
		return
	}

	if coterie.Owner != ownerID {
		http.Error(w, "Unauthorized. Only the coterie owner can update the warning limit.", http.StatusUnauthorized)
		return
	}

	filter := bson.M{"name": name, "owner": ownerID}
	update := bson.M{"$set": bson.M{"warningLimit": limit}}

	_, err = coterieCollection.UpdateOne(context.Background(), filter, update)
	if err != nil {
		http.Error(w, "Failed to update warning limit.", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":      "Warning limit updated",
		"warningLimit": limit,
	})
}

func UpdateCoterie(w http.ResponseWriter, r *http.Request) {
	db := r.Context().Value("db").(*mongo.Client)
	coterieCollection := db.Database("SocialFlux").Collection("coterie")

	newName := r.URL.Query().Get("newName")
	coterieName := r.URL.Query().Get("name")
	newDescription := r.URL.Query().Get("newDescription")
	ownerID := r.URL.Query().Get("ownerID")
	newBanner := r.URL.Query().Get("newBanner")
	newAvatar := r.URL.Query().Get("newAvatar")
	isChatAllowedStr := r.URL.Query().Get("isChatAllowed")

	ownerObjectID, err := primitive.ObjectIDFromHex(ownerID)
	if err != nil {
		http.Error(w, "Invalid owner ID", http.StatusBadRequest)
		return
	}

	filter := bson.M{"name": coterieName, "owner": ownerObjectID}

	updateFields := bson.M{}
	if newName != "" {
		updateFields["name"] = newName
	}
	if newDescription != "" {
		updateFields["description"] = newDescription
	}
	if newBanner != "" {
		updateFields["banner"] = newBanner
	}
	if newAvatar != "" {
		updateFields["avatar"] = newAvatar
	}

	if isChatAllowedStr != "" {
		isChatAllowed, err := strconv.ParseBool(isChatAllowedStr)
		if err != nil {
			http.Error(w, "Invalid value for IsChatAllowed, must be true or false", http.StatusBadRequest)
			return
		}
		updateFields["isChatAllowed"] = isChatAllowed
	}

	update := bson.M{"$set": updateFields}

	result, err := coterieCollection.UpdateOne(context.Background(), filter, update)
	if err != nil {
		http.Error(w, "Failed to update coterie", http.StatusInternalServerError)
		return
	}

	if result.ModifiedCount == 0 {
		http.Error(w, "Coterie not found or you are not the owner", http.StatusNotFound)
		return
	}

	response := map[string]interface{}{
		"message": "Coterie updated successfully",
		"updates": updateFields,
	}

	json.NewEncoder(w).Encode(response)
}

func WarnMember(w http.ResponseWriter, r *http.Request) {
	db := r.Context().Value("db").(*mongo.Client)

	coterieCollection := db.Database("SocialFlux").Collection("coterie")
	userCollection := db.Database("SocialFlux").Collection("users")

	name := r.URL.Query().Get("CoterieName")
	membername := r.URL.Query().Get("username")
	modIDStr := r.URL.Query().Get("modID")
	reason := r.URL.Query().Get("reason")

	if name == "" || membername == "" || modIDStr == "" || reason == "" {
		http.Error(w, "All query parameters are required", http.StatusBadRequest)
		return
	}

	modID, err := primitive.ObjectIDFromHex(modIDStr)
	if err != nil {
		http.Error(w, "Invalid modID format", http.StatusBadRequest)
		return
	}

	var member bson.M
	err = userCollection.FindOne(context.TODO(), bson.M{"username": membername}).Decode(&member)
	if err != nil {
		http.Error(w, "Member not found", http.StatusNotFound)
		return
	}

	var mod bson.M
	err = userCollection.FindOne(context.TODO(), bson.M{"_id": modID}).Decode(&mod)
	if err != nil {
		http.Error(w, "Mod not found", http.StatusNotFound)
		return
	}

	memberID := member["_id"].(primitive.ObjectID).Hex()

	var coterie types.Coterie
	err = coterieCollection.FindOne(context.TODO(), bson.M{"name": name}).Decode(&coterie)
	if err != nil {
		http.Error(w, "Coterie not found", http.StatusNotFound)
		return
	}

	isMember := false
	for _, memberIDInCoterie := range coterie.Members {
		if memberIDInCoterie == memberID {
			isMember = true
			break
		}
	}

	if !isMember {
		http.Error(w, "The user is not a member of the coterie", http.StatusBadRequest)
		return
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
		http.Error(w, "Unauthorized. Only owners, admins, or moderators can warn members.", http.StatusUnauthorized)
		return
	}

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
		http.Error(w, "Failed to update coterie", http.StatusInternalServerError)
		return
	}

	if len(updatedCoterie.WarningDetails[memberID]) > updatedCoterie.WarningLimit {
		filter := bson.M{"name": name, "owner": coterie.Owner}
		update := bson.M{
			"$pull": bson.M{"members": memberID},
		}

		opts := options.Update().SetUpsert(false)
		_, err := coterieCollection.UpdateOne(context.TODO(), filter, update, opts)
		if err != nil {
			http.Error(w, "Failed to remove member", http.StatusInternalServerError)
			return
		}

		updateWarning := bson.M{
			"$unset": bson.M{"warningDetails." + memberID: ""},
		}

		_, err = coterieCollection.UpdateOne(context.TODO(), filter, updateWarning, opts)
		if err != nil {
			http.Error(w, "Failed to remove member's warning details", http.StatusInternalServerError)
			return
		}

		json.NewEncoder(w).Encode(map[string]string{"message": fmt.Sprintf("User removed because they reached the warning limit %d", updatedCoterie.WarningLimit)})
		return
	}

	json.NewEncoder(w).Encode(map[string]string{
		"message": fmt.Sprintf("Member %s is successfully warned for reason: %s", membername, reason),
	})
}

func PromoteMember(w http.ResponseWriter, r *http.Request) {
	db := r.Context().Value("db").(*mongo.Client)

	coterieCollection := db.Database("SocialFlux").Collection("coterie")
	userCollection := db.Database("SocialFlux").Collection("users")

	coterieName := r.FormValue("CoterieName")
	role := r.FormValue("role")
	memberName := r.FormValue("username")
	promoterIDStr := r.FormValue("modID")
	action := r.FormValue("action")

	promoterID, err := primitive.ObjectIDFromHex(promoterIDStr)
	if err != nil {
		http.Error(w, "Invalid PromoterID", http.StatusBadRequest)
		return
	}

	var member struct {
		ID primitive.ObjectID `bson:"_id"`
	}
	err = userCollection.FindOne(context.TODO(), bson.M{"username": memberName}).Decode(&member)
	if err != nil {
		http.Error(w, "Member not found", http.StatusNotFound)
		return
	}

	var coterie types.Coterie
	err = coterieCollection.FindOne(context.TODO(), bson.M{"name": coterieName}).Decode(&coterie)
	if err != nil {
		http.Error(w, "Coterie not found", http.StatusNotFound)
		return
	}

	if coterie.Owner != promoterID {
		http.Error(w, "Only the owner can promote or demote members", http.StatusUnauthorized)
		return
	}

	if role != "moderators" && role != "admins" {
		http.Error(w, "Invalid role. Must be 'moderators' or 'admins'", http.StatusBadRequest)
		return
	}

	if action != "promote" && action != "demote" {
		http.Error(w, "Invalid action. Must be 'promote' or 'demote'", http.StatusBadRequest)
		return
	}

	var update bson.M
	if action == "promote" {
		update = bson.M{
			"$addToSet": bson.M{
				"roles." + role: member.ID.Hex(),
			},
		}
	} else {
		update = bson.M{
			"$pull": bson.M{
				"roles." + role: member.ID.Hex(),
			},
		}
	}

	_, err = coterieCollection.UpdateOne(context.TODO(), bson.M{"name": coterieName}, update)
	if err != nil {
		http.Error(w, "Failed to update coterie", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{
		"message": fmt.Sprintf("Member %s successfully %s to %s", memberName, action+"d", role),
	})
}

func RemovePostFromCoterie(w http.ResponseWriter, r *http.Request) {
	db, ok := r.Context().Value("db").(*mongo.Client)
	if !ok {
		http.Error(w, "Database connection not available", http.StatusInternalServerError)
		return
	}

	coterieCollection := db.Database("SocialFlux").Collection("coterie")
	postCollection := db.Database("SocialFlux").Collection("posts")
	userCollection := db.Database("SocialFlux").Collection("users")

	// Parse request parameters
	coterieName := r.URL.Query().Get("coterie")
	postIDStr := r.URL.Query().Get("postID")
	modIDStr := r.URL.Query().Get("modID")

	modID, err := primitive.ObjectIDFromHex(modIDStr)
	if err != nil {
		http.Error(w, "Invalid moderator ID", http.StatusBadRequest)
		return
	}

	// Fetch coterie details
	var coterie types.Coterie
	err = coterieCollection.FindOne(context.Background(), bson.M{"name": coterieName}).Decode(&coterie)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			http.Error(w, "Coterie not found", http.StatusNotFound)
			return
		}
		http.Error(w, "Error fetching coterie: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Fetch post details
	var post types.Post
	err = postCollection.FindOne(context.Background(), bson.M{"_id": postIDStr}).Decode(&post)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			http.Error(w, "Post not found", http.StatusNotFound)
			return
		}
		http.Error(w, "Error fetching post: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Check if the post belongs to the specified coterie
	if post.Coterie != coterieName {
		http.Error(w, "Post does not belong to the specified coterie", http.StatusBadRequest)
		return
	}

	// Fetch user details
	var mod types.User
	err = userCollection.FindOne(context.Background(), bson.M{"_id": modID}).Decode(&mod)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			http.Error(w, "Moderator not found", http.StatusNotFound)
			return
		}
		http.Error(w, "Error fetching moderator: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Check if the modID is an authorized moderator or owner
	isAuthorized := false
	for _, ownerID := range coterie.Roles["owners"] {
		if ownerID == modIDStr {
			isAuthorized = true
			break
		}
	}
	if !isAuthorized {
		for _, adminID := range coterie.Roles["admins"] {
			if adminID == modIDStr {
				isAuthorized = true
				break
			}
		}
	}
	if !isAuthorized {
		for _, modID := range coterie.Roles["moderators"] {
			if modID == modIDStr {
				isAuthorized = true
				break
			}
		}
	}

	if !isAuthorized {
		http.Error(w, "Unauthorized. Only owners, admins, or moderators can remove posts.", http.StatusUnauthorized)
		return
	}

	// Remove the post from the posts collection
	result, err := postCollection.DeleteOne(context.Background(), bson.M{"_id": postIDStr})
	if err != nil {
		http.Error(w, "Error removing post: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if result.DeletedCount == 0 {
		http.Error(w, "Post not found or already removed", http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"message": "Post removed successfully"}`))
}

func BanUser(w http.ResponseWriter, r *http.Request) {
	db, ok := r.Context().Value("db").(*mongo.Client)
	if !ok {
		http.Error(w, "Database connection not available", http.StatusInternalServerError)
		return
	}

	coterieCollection := db.Database("SocialFlux").Collection("coterie")
	userCollection := db.Database("SocialFlux").Collection("users")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Parse query parameters
	coterieName := r.URL.Query().Get("CoterieName")
	username := r.URL.Query().Get("username")
	modID := r.URL.Query().Get("modID")

	// Fetch moderator details
	var moderator types.User
	moderatorObjectID, err := primitive.ObjectIDFromHex(modID)
	if err != nil {
		http.Error(w, "Invalid moderator ID", http.StatusBadRequest)
		return
	}
	err = userCollection.FindOne(ctx, bson.M{"_id": moderatorObjectID}).Decode(&moderator)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			http.Error(w, "Moderator not found", http.StatusNotFound)
			return
		}
		http.Error(w, "Error fetching moderator: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Fetch coterie details
	var coterie types.Coterie
	err = coterieCollection.FindOne(ctx, bson.M{"name": coterieName}).Decode(&coterie)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			http.Error(w, "Coterie not found", http.StatusNotFound)
			return
		}
		http.Error(w, "Error fetching coterie: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Fetch user details
	var user types.User
	err = userCollection.FindOne(ctx, bson.M{"username": username}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}
		http.Error(w, "Error fetching user: "+err.Error(), http.StatusInternalServerError)
		return
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
		http.Error(w, "User is not a member of this coterie", http.StatusBadRequest)
		return
	}

	// Add user to bannedMembers array in coterie document
	update := bson.M{
		"$push": bson.M{
			"bannedMembers": user.ID.Hex(),
		},
	}
	_, err = coterieCollection.UpdateOne(ctx, bson.M{"_id": coterie.ID}, update)
	if err != nil {
		http.Error(w, "Error updating coterie: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Mark user as banned in users collection
	updateUser := bson.M{
		"$set": bson.M{
			"isBanned": true,
		},
	}
	_, err = userCollection.UpdateOne(ctx, bson.M{"_id": user.ID}, updateUser)
	if err != nil {
		http.Error(w, "Error updating user: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Return success response
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"message": "User '%s' has been banned from coterie '%s' by moderator '%s'"}`, username, coterieName, moderator.Username)
}

func GetCoteriesByUserID(w http.ResponseWriter, r *http.Request) {
	// Retrieve the database client from the context
	db, ok := r.Context().Value("db").(*mongo.Client)
	if !ok {
		http.Error(w, "Database connection not available", http.StatusInternalServerError)
		return
	}

	// Retrieve the parameter from the request
	param := chi.URLParam(r, "userParam")

	var userID primitive.ObjectID
	var err error

	// Check if the parameter is a valid ObjectID
	if primitive.IsValidObjectID(param) {
		userID, err = primitive.ObjectIDFromHex(param)
		if err != nil {
			http.Error(w, "Invalid user ID", http.StatusBadRequest)
			return
		}
	} else {
		// Treat the parameter as a username and fetch the user ID
		userCollection := db.Database("SocialFlux").Collection("users")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		var user struct {
			ID primitive.ObjectID `bson:"_id"`
		}

		err = userCollection.FindOne(ctx, bson.M{"username": param}).Decode(&user)
		if err != nil {
			if err == mongo.ErrNoDocuments {
				http.Error(w, "User not found", http.StatusNotFound)
			} else {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			return
		}
		userID = user.ID
	}

	// Fetch the coteries by user ID
	coterieCollection := db.Database("SocialFlux").Collection("coterie")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Find coteries where the user is a member
	cursor, err := coterieCollection.Find(ctx, bson.M{"members": userID.Hex()})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer cursor.Close(ctx)

	var coteries []map[string]interface{}
	for cursor.Next(ctx) {
		var coterie types.Coterie

		if err := cursor.Decode(&coterie); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Determine user roles in the coterie
		isOwner := coterie.Owner == userID
		isAdmin := contains(coterie.Roles["admin"], userID.Hex())
		isModerator := contains(coterie.Roles["moderator"], userID.Hex())

		coteries = append(coteries, map[string]interface{}{
			"name":           coterie.Name,
			"avatar":         coterie.Avatar,
			"isVerified":     coterie.IsVerified,
			"isChatAllowed":  coterie.IsChatAllowed,
			"isOwner":        isOwner,
			"isOrganisation": coterie.IsOrganisation,
			"isAdmin":        isAdmin,
			"TotalMembers":   len(coterie.Members),
			"isModerator":    isModerator,
		})
	}

	if err := cursor.Err(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Return the list of coteries as JSON
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(coteries); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// Helper function to check if a user ID exists in a slice
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func CoterieRoutes(r chi.Router) {
	r.Get("/coterie/@all", GetAllCoterie)
	r.With(RateLimit(5, 5*time.Minute)).Post("/coterie/leave", (middlewares.DiscordErrorReport(http.HandlerFunc(LeaveCoterie)).ServeHTTP))
	r.With(RateLimit(5, 5*time.Minute)).Post("/coterie/set-warning-limit", (middlewares.DiscordErrorReport(http.HandlerFunc(SetWarningLimit)).ServeHTTP))
	r.Get("/coterie/{name}", GetCoterieByName)
	r.Get("/user/{userParam}/coteries", GetCoteriesByUserID)
	r.With(RateLimit(5, 5*time.Minute)).Delete("/coterie/remove-post", (middlewares.DiscordErrorReport(http.HandlerFunc(RemovePostFromCoterie)).ServeHTTP))
	r.With(RateLimit(5, 5*time.Minute)).Post("/coterie/update", (middlewares.DiscordErrorReport(http.HandlerFunc(UpdateCoterie)).ServeHTTP))
	r.With(RateLimit(5, 5*time.Minute)).Post("/coterie/join", (middlewares.DiscordErrorReport(http.HandlerFunc(JoinCoterie)).ServeHTTP))
	r.With(RateLimit(5, 5*time.Minute)).Post("/coterie/promote", (middlewares.DiscordErrorReport(http.HandlerFunc(PromoteMember)).ServeHTTP))
	r.With(RateLimit(5, 5*time.Minute)).Post("/coterie/ban", (middlewares.DiscordErrorReport(http.HandlerFunc(BanUser)).ServeHTTP))
	r.With(RateLimit(5, 5*time.Minute)).Post("/coterie/warn", (middlewares.DiscordErrorReport(http.HandlerFunc(WarnMember)).ServeHTTP))
	r.With(RateLimit(1, 20*time.Minute)).Post("/coterie/new", (middlewares.DiscordErrorReport(http.HandlerFunc(AddNewCoterie)).ServeHTTP))
}
