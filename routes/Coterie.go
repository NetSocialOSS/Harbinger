package routes

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgtype"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/lib/pq"

	"netsocial/database"
	"netsocial/middlewares"
	"netsocial/types"
)

var (
	coterie types.Coterie
)

func getUserDetails(db *pgxpool.Pool, userID uuid.UUID, cache map[uuid.UUID]map[string]string) (map[string]string, error) {
	if userDetails, exists := cache[userID]; exists {
		return userDetails, nil
	}

	var user types.User
	err := db.QueryRow(context.Background(), `SELECT id, username, profilepicture FROM users WHERE id = $1`, userID).Scan(&user.ID, &user.Username, &user.ProfilePicture)
	if err != nil {
		return nil, err
	}

	userDetails := map[string]string{
		"username":       user.Username,
		"profilePicture": user.ProfilePicture,
	}

	cache[userID] = userDetails
	return userDetails, nil
}

func GetAllCoterie(w http.ResponseWriter, r *http.Request) {
	db := r.Context().Value(database.DBContextKey).(*pgxpool.Pool)

	rows, err := db.Query(context.Background(), `
			SELECT id, name, description, createdat, avatar, banner, members, isVerified, isOrganisation
			FROM coterie
			ORDER BY createdat ASC;
	`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var result []map[string]interface{}

	for rows.Next() {
		var coterie types.Coterie
		if err := rows.Scan(&coterie.ID, &coterie.Name, &coterie.Description, &coterie.CreatedAt, &coterie.Avatar, &coterie.Banner, &coterie.Members, &coterie.IsVerified, &coterie.IsOrganisation); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		var postCount int
		err = db.QueryRow(context.Background(), `
					SELECT COUNT(*) FROM post WHERE coterie = $1
			`, coterie.Name).Scan(&postCount)
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
			"TotalMembers":   len(coterie.Members),
			"PostsCount":     postCount,
		}

		if coterie.Avatar != nil && *coterie.Avatar != "" {
			coterieMap["avatar"] = *coterie.Avatar
		}

		if coterie.Banner != nil && *coterie.Banner != "" {
			coterieMap["banner"] = *coterie.Banner
		}
		result = append(result, coterieMap)
	}

	if err := rows.Err(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(result)
}

func GetCoterieByName(w http.ResponseWriter, r *http.Request) {
	// Get the PostgreSQL connection from the context
	db, ok := r.Context().Value(database.DBContextKey).(*pgxpool.Pool)
	if !ok {
		http.Error(w, "Database connection not found", http.StatusInternalServerError)
		return
	}

	// Get URL parameters
	coterieName := chi.URLParam(r, "name")
	action := r.URL.Query().Get("action")

	// Query for the coterie by name
	var coterie types.Coterie
	var rolesJSON []byte

	err := db.QueryRow(context.Background(), `
	SELECT id, name, description, members, owner, createdat, banner, avatar, isChatAllowed, isVerified, isOrganisation, roles, bannedmembers
	FROM coterie WHERE name ILIKE $1
`, coterieName).Scan(
		&coterie.ID,
		&coterie.Name,
		&coterie.Description,
		&coterie.Members,
		&coterie.Owner,
		&coterie.CreatedAt,
		&coterie.Banner,
		&coterie.Avatar,
		&coterie.IsChatAllowed,
		&coterie.IsVerified,
		&coterie.IsOrganisation,
		&rolesJSON,
		&coterie.BannedMembers,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			http.Error(w, "Coterie not found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// After scanning, unmarshal the roles JSONB data into the map
	if len(rolesJSON) > 0 {
		err = json.Unmarshal(rolesJSON, &coterie.Roles)
		if err != nil {
			http.Error(w, "Failed to unmarshal roles JSON", http.StatusInternalServerError)
			return
		}
	}

	userIDToDetails := make(map[uuid.UUID]map[string]string)

	// Get owner details
	ownerUUID, err := uuid.Parse(coterie.Owner)
	if err != nil {
		http.Error(w, "Invalid owner ID", http.StatusInternalServerError)
		return
	}
	ownerDetails, err := getUserDetails(db, ownerUUID, userIDToDetails)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Get members' details
	var memberDetails []map[string]interface{}
	for _, memberID := range coterie.Members {
		memberUUID, err := uuid.Parse(memberID)
		if err != nil {
			memberDetails = append(memberDetails, map[string]interface{}{
				"username":       "Invalid ID",
				"profilePicture": "",
			})
			continue
		}
		details, err := getUserDetails(db, memberUUID, userIDToDetails)
		if err != nil {
			memberDetails = append(memberDetails, map[string]interface{}{
				"username":       "Unknown User",
				"profilePicture": "",
			})
			continue
		}
		memberDetails = append(memberDetails, map[string]interface{}{
			"username":       details["username"],
			"profilePicture": details["profilePicture"],
		})
	}

	// Prepare basic response structure
	result := map[string]interface{}{
		"name":           coterie.Name,
		"description":    coterie.Description,
		"owner":          ownerDetails,
		"isVerified":     coterie.IsVerified,
		"isOrganisation": coterie.IsOrganisation,
		"createdAt":      coterie.CreatedAt,
		"isChatAllowed":  coterie.IsChatAllowed,
		"TotalMembers":   len(memberDetails),
	}

	if coterie.Avatar != nil && *coterie.Avatar != "" {
		result["avatar"] = *coterie.Avatar
	}

	if coterie.Banner != nil && *coterie.Banner != "" {
		result["banner"] = *coterie.Banner
	}

	// Handle members-only action
	if action == "members" {
		membersResponse := map[string]interface{}{
			"members": memberDetails,
		}
		json.NewEncoder(w).Encode(membersResponse)
		return
	}

	// Handle info-only action
	if action == "info" {
		json.NewEncoder(w).Encode(result)
		return
	}

	// Count posts for the coterie
	var postCount int
	err = db.QueryRow(context.Background(), `SELECT COUNT(*) FROM post WHERE coterie = $1`, coterie.Name).Scan(&postCount)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	result["TotalPosts"] = postCount

	// Fetch posts if action is "posts" or unspecified
	var posts []map[string]interface{}
	if action == "posts" || action == "" || action == "all" {

		rows, err := db.Query(context.Background(), `
			SELECT id, title, content, author, scheduledfor, image, hearts, createdat, poll, comments
			FROM post WHERE coterie = $1 ORDER BY createdat DESC
		`, coterie.Name)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()
		var scheduledFor pgtype.Timestamp
		var pollJSON *json.RawMessage
		var commentsJSON pgtype.Text

		for rows.Next() {
			var post types.Post
			err := rows.Scan(&post.ID, &post.Title, &post.Content, &post.Author, &scheduledFor, &post.Image, &post.Hearts, &post.CreatedAt, &pollJSON, &commentsJSON)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			if commentsJSON.Status == pgtype.Present {
				var commentList []types.Comment
				if err := json.Unmarshal([]byte(commentsJSON.String), &commentList); err != nil {
					http.Error(w, fmt.Sprintf("Failed to decode comments: %v", err), http.StatusInternalServerError)
					return
				}
				post.Comments = commentList
			} else {
				post.Comments = []types.Comment{}
			}

			// Only unmarshal poll if it is not nil
			if pollJSON != nil {
				if err := json.Unmarshal(*pollJSON, &post.Poll); err != nil {
					http.Error(w, "Error decoding poll data: "+err.Error(), http.StatusInternalServerError)
					return
				}
			}

			if scheduledFor.Status == pgtype.Present {
				post.ScheduledFor = scheduledFor.Time
			} else {
				post.ScheduledFor = time.Time{} // Default zero value for time.Time
			}

			var author types.User
			err = db.QueryRow(context.Background(), `SELECT id, username, profilepicture, profilebanner, isverified, isorganisation, isdeveloper, ispartner, isowner, ismoderator FROM users WHERE id = $1`, post.Author).Scan(&author.ID, &author.Username, &author.ProfilePicture, &author.ProfileBanner, &author.IsVerified, &author.IsOrganisation, &author.IsDeveloper, &author.IsPartner, &author.IsOwner, &author.IsModerator)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			var heartsDetails []string
			for _, heartID := range post.Hearts {
				heartUUID, err := uuid.Parse(heartID)
				if err != nil {
					heartsDetails = append(heartsDetails, "Invalid ID")
					continue
				}
				details, err := getUserDetails(db, heartUUID, userIDToDetails)
				if err != nil {
					heartsDetails = append(heartsDetails, "Unknown User")
					continue
				}
				heartsDetails = append(heartsDetails, details["username"])
			}
			// Process polls
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
			if scheduledFor.Status == pgtype.Present && !post.ScheduledFor.IsZero() && post.ScheduledFor.After(now) {
				continue
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
					"username":       author.Username,
				},
			}
			if !post.ScheduledFor.IsZero() {
				postMap["scheduledFor"] = post.ScheduledFor
			}
			posts = append(posts, postMap)
		}

		if action == "posts" {
			json.NewEncoder(w).Encode(map[string]interface{}{"Post": posts})
			return
		}
		result["Post"] = posts
	}

	json.NewEncoder(w).Encode(result)
}

func AddNewCoterie(w http.ResponseWriter, r *http.Request) {
	db := r.Context().Value(database.DBContextKey).(*pgxpool.Pool)

	title := r.Header.Get("X-name")

	// Decrypt the user ID
	encrypteduserId := r.Header.Get("X-userID")
	if encrypteduserId == "" {
		http.Error(w, "userId query parameter is required", http.StatusBadRequest)
		return
	}

	owner, err := middlewares.DecryptAES(encrypteduserId)
	if err != nil {
		http.Error(w, "Failed to decrypt userid", http.StatusBadRequest)
		return
	}

	if title == "" {
		http.Error(w, "Coterie name cannot be blank", http.StatusBadRequest)
		return
	}

	// Ensure the user struct matches the correct type for the database schema
	var user types.User
	err = db.QueryRow(context.Background(), "SELECT id FROM users WHERE id = $1", owner).Scan(&user.ID)
	if err != nil {
		http.Error(w, "Error checking owner existence: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Check if the user is banned
	if user.IsBanned {
		http.Error(w, "User is banned", http.StatusForbidden)
		return
	}

	// Check if the coterie already exists
	var existingCoterie types.Coterie
	err = db.QueryRow(context.Background(), "SELECT name FROM coterie WHERE name = $1", title).Scan(&existingCoterie.Name)
	if err == nil {
		http.Error(w, "A coterie with this name already exists", http.StatusConflict)
		return
	}

	// Insert the new coterie
	_, err = db.Exec(context.Background(), `
    INSERT INTO coterie (name, description, members, owner, createdat)
    VALUES ($1, $2, $3, $4, $5)`,
		title, "", []string{owner}, owner, time.Now(),
	)
	if err != nil {
		http.Error(w, "Failed to create coterie: "+err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"name":      title,
		"createdAt": time.Now(),
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

func CoterieMembership(w http.ResponseWriter, r *http.Request) {
	db := r.Context().Value(database.DBContextKey).(*pgxpool.Pool)

	coterieName := r.Header.Get("X-name")
	action := r.Header.Get("X-action")

	encrypteduserId := r.Header.Get("X-userID")
	if encrypteduserId == "" {
		http.Error(w, "userId query parameter is required", http.StatusBadRequest)
		return
	}

	userID, err := middlewares.DecryptAES(encrypteduserId)
	if err != nil {
		http.Error(w, "Failed to decrypt userid", http.StatusBadRequest)
		return
	}

	// Check if user exists
	var user types.User
	err = db.QueryRow(context.Background(), "SELECT username FROM users WHERE id = $1", userID).Scan(&user.Username)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			http.Error(w, "User not found", http.StatusNotFound)
		} else {
			http.Error(w, "Database error", http.StatusInternalServerError)
		}
		return
	}

	if user.IsBanned {
		http.Error(w, "User is banned", http.StatusForbidden)
		return
	}

	// Find coterie
	var coterie types.Coterie
	err = db.QueryRow(context.Background(), "SELECT id FROM coterie WHERE name = $1", coterieName).Scan(&coterie.Name)
	if err != nil {
		http.Error(w, "Coterie not found", http.StatusNotFound)
		return
	}

	switch action {
	case "join":
		// Add user to the coterie
		_, err = db.Exec(context.Background(), `
					UPDATE coterie SET members = array_append(members, $1) WHERE name = $2`,
			userID, coterieName,
		)
		if err != nil {
			http.Error(w, "Failed to join coterie: "+err.Error(), http.StatusInternalServerError)
			return
		}

		response := map[string]interface{}{
			"message": fmt.Sprintf("You have successfully joined '%s'", coterieName),
		}
		json.NewEncoder(w).Encode(response)

	case "leave":
		// Remove user from coterie
		_, err = db.Exec(context.Background(), `
					UPDATE coterie SET members = array_remove(members, $1) WHERE name = $2`,
			userID, coterieName,
		)
		if err != nil {
			http.Error(w, "Failed to leave coterie: "+err.Error(), http.StatusInternalServerError)
			return
		}

		response := map[string]interface{}{
			"message": fmt.Sprintf("You have successfully left '%s'", coterieName),
		}
		json.NewEncoder(w).Encode(response)

	default:
		http.Error(w, "Invalid action. Use 'join' or 'leave'", http.StatusBadRequest)
	}
}

func SetWarningLimit(w http.ResponseWriter, r *http.Request) {
	db := r.Context().Value(database.DBContextKey).(*pgxpool.Pool)

	name := r.URL.Query().Get("name")
	limitStr := r.URL.Query().Get("limitnumber")

	encrypteduserId := r.Header.Get("X-userID")
	if encrypteduserId == "" {
		http.Error(w, "userId query parameter is required", http.StatusBadRequest)
		return
	}

	ownerID, err := middlewares.DecryptAES(encrypteduserId)
	if err != nil {
		http.Error(w, "Failed to decrypt userid", http.StatusBadRequest)
		return
	}

	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit < 1 || limit > 9 {
		http.Error(w, "Invalid warning limit. Must be between 1 and 9.", http.StatusBadRequest)
		return
	}

	var dbOwnerID uuid.UUID
	var dbWarningLimit int
	err = db.QueryRow(r.Context(), `SELECT owner, warninglimit FROM coterie WHERE name = $1`, name).Scan(&dbOwnerID, &dbWarningLimit)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			http.Error(w, "Coterie not found.", http.StatusNotFound)
		} else {
			http.Error(w, "Error fetching coterie details.", http.StatusInternalServerError)
		}
		return
	}

	ownerUUID, err := uuid.Parse(ownerID)
	if err != nil {
		http.Error(w, "Invalid owner ID", http.StatusBadRequest)
		return
	}
	if dbOwnerID != ownerUUID {
		http.Error(w, "Unauthorized. Only the coterie owner can update the warning limit.", http.StatusUnauthorized)
		return
	}

	_, err = db.Exec(r.Context(), `UPDATE coterie SET warninglimit = $1 WHERE name = $2 AND owner = $3`, limit, name, ownerID)
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
	db := r.Context().Value(database.DBContextKey).(*pgxpool.Pool)

	newName := r.URL.Query().Get("newName")
	coterieName := r.URL.Query().Get("name")
	newDescription := r.URL.Query().Get("newDescription")
	newBanner := r.URL.Query().Get("newBanner")
	newAvatar := r.URL.Query().Get("newAvatar")
	isChatAllowedStr := r.URL.Query().Get("isChatAllowed")

	encrypteduserId := r.Header.Get("X-userID")
	if encrypteduserId == "" {
		http.Error(w, "userId query parameter is required", http.StatusBadRequest)
		return
	}

	ownerID, err := middlewares.DecryptAES(encrypteduserId)
	if err != nil {
		http.Error(w, "Failed to decrypt userid", http.StatusBadRequest)
		return
	}

	updateFields := []string{}
	updateValues := []interface{}{}

	index := 1
	if newName != "" {
		updateFields = append(updateFields, fmt.Sprintf("name = $%d", index))
		updateValues = append(updateValues, newName)
		index++
	}
	if newDescription != "" {
		updateFields = append(updateFields, fmt.Sprintf("description = $%d", index))
		updateValues = append(updateValues, newDescription)
		index++
	}
	if newBanner != "" {
		updateFields = append(updateFields, fmt.Sprintf("banner = $%d", index))
		updateValues = append(updateValues, newBanner)
		index++
	}
	if newAvatar != "" {
		updateFields = append(updateFields, fmt.Sprintf("avatar = $%d", index))
		updateValues = append(updateValues, newAvatar)
		index++
	}
	if isChatAllowedStr != "" {
		isChatAllowed, err := strconv.ParseBool(isChatAllowedStr)
		if err != nil {
			http.Error(w, "Invalid value for IsChatAllowed, must be true or false", http.StatusBadRequest)
			return
		}
		updateFields = append(updateFields, fmt.Sprintf("isChatAllowed = $%d", index))
		updateValues = append(updateValues, isChatAllowed)
		index++
	}

	if len(updateFields) == 0 {
		http.Error(w, "No fields to update", http.StatusBadRequest)
		return
	}

	query := fmt.Sprintf(`
			UPDATE coterie
			SET %s
			WHERE LOWER(name) = LOWER($%d) AND owner = $%d
			RETURNING id, name, description, banner, avatar, isChatAllowed, owner`,
		strings.Join(updateFields, ", "), index, index+1)

	updateValues = append(updateValues, coterieName, ownerID)

	row := db.QueryRow(r.Context(), query, updateValues...)

	var coterie types.Coterie
	if err := row.Scan(&coterie.ID, &coterie.Name, &coterie.Description, &coterie.Banner, &coterie.Avatar, &coterie.IsChatAllowed, &coterie.Owner); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			http.Error(w, "Coterie not found or you are not the owner", http.StatusNotFound)
		} else {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	response := map[string]interface{}{
		"message": "Coterie updated successfully",
		"coterie": coterie,
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}

func WarnMember(w http.ResponseWriter, r *http.Request) {
	db := r.Context().Value(database.DBContextKey).(*pgxpool.Pool)

	coterieName := r.URL.Query().Get("CoterieName")
	membername := r.URL.Query().Get("username")
	reason := r.URL.Query().Get("reason")

	encrypteduserId := r.Header.Get("X-userID")
	if encrypteduserId == "" {
		http.Error(w, "userId query parameter is required", http.StatusBadRequest)
		return
	}

	modID, err := middlewares.DecryptAES(encrypteduserId)
	if err != nil {
		http.Error(w, "Failed to decrypt userid", http.StatusBadRequest)
		return
	}

	var member types.User
	err = db.QueryRow(r.Context(), `SELECT id FROM users WHERE username = $1`, membername).Scan(&member.ID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			http.Error(w, "Member not found", http.StatusNotFound)
		} else {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	var coterie types.Coterie
	var warningDetailsJson []byte
	var owner uuid.UUID
	var rolesText pgtype.Text
	err = db.QueryRow(r.Context(), `
			SELECT id, members, warningDetails, roles, owner
			FROM coterie WHERE name = $1`, coterieName).Scan(&coterie.ID, pq.Array(&coterie.Members), &warningDetailsJson, &rolesText, &owner)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			http.Error(w, "Coterie not found", http.StatusNotFound)
		} else {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	if len(warningDetailsJson) > 0 {
		err = json.Unmarshal(warningDetailsJson, &coterie.WarningDetails)
		if err != nil {
			http.Error(w, "Failed to process warning details", http.StatusInternalServerError)
			return
		}
	}

	isAuthorized := false
	roles := []string{owner.String()}
	if rolesText.Status == pgtype.Present {
		roles = append(roles, strings.Split(rolesText.String, ",")...)
	}

	for _, role := range roles {
		if role == modID {
			isAuthorized = true
			break
		}
	}

	if !isAuthorized {
		http.Error(w, "Unauthorized. Only owners, admins, or moderators can warn members.", http.StatusUnauthorized)
		return
	}

	_, err = db.Exec(r.Context(), `
			UPDATE coterie
			SET warningDetails = jsonb_set(
					COALESCE(warningDetails, '{}'::jsonb),
					array[$1::text],
					jsonb_build_object('reason', $2::text, 'time', $3::timestamp)
			)
			WHERE name = $4`,
		member.ID, reason, time.Now().Format(time.RFC3339), coterieName)
	if err != nil {
		http.Error(w, "Failed to warn member", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{
		"message": fmt.Sprintf("Member %s successfully warned for reason: %s", membername, reason),
	})
}

func PromoteMember(w http.ResponseWriter, r *http.Request) {
	db, ok := r.Context().Value(database.DBContextKey).(*pgxpool.Pool)
	if !ok {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	coterieName := r.URL.Query().Get("CoterieName")
	role := r.URL.Query().Get("role")
	memberName := r.URL.Query().Get("username")
	action := r.URL.Query().Get("action")

	encrypteduserId := r.Header.Get("X-userID")
	if encrypteduserId == "" {
		http.Error(w, "userId query parameter is required", http.StatusBadRequest)
		return
	}

	promoterID, err := middlewares.DecryptAES(encrypteduserId)
	if err != nil {
		http.Error(w, "Failed to decrypt userid", http.StatusBadRequest)
		return
	}

	var memberID uuid.UUID
	err = db.QueryRow(r.Context(), `SELECT id FROM users WHERE username = $1`, memberName).Scan(&memberID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			http.Error(w, "Member not found", http.StatusNotFound)
		} else {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	var coterieID uuid.UUID
	var ownerID uuid.UUID
	var rolesJson pgtype.Text
	err = db.QueryRow(r.Context(),
		`SELECT id, owner, roles FROM coterie WHERE name = $1`,
		coterieName,
	).Scan(&coterieID, &ownerID, &rolesJson)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			http.Error(w, "Coterie not found", http.StatusNotFound)
		} else {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	promoterUUID, err := uuid.Parse(promoterID)
	if err != nil {
		http.Error(w, "Invalid promoter ID", http.StatusBadRequest)
		return
	}
	if ownerID != promoterUUID {
		http.Error(w, "Only the owner can promote/demote", http.StatusUnauthorized)
		return
	}

	validRoles := map[string]bool{"Moderator": true, "Admin": true, "Owner": true}
	if !validRoles[role] {
		http.Error(w, "Invalid role", http.StatusBadRequest)
		return
	}

	if action != "promote" && action != "demote" {
		http.Error(w, "Invalid action", http.StatusBadRequest)
		return
	}

	updateQuery := `UPDATE coterie SET roles = jsonb_set(
			COALESCE(roles, '{}'::jsonb),
			$1,
			CASE WHEN $2 = 'promote' 
					THEN COALESCE(roles->$3, '[]'::jsonb) || to_jsonb($4::text)
					ELSE COALESCE(roles->$3, '[]'::jsonb) - to_jsonb($4::text)
			END
	) WHERE id = $5`

	path := fmt.Sprintf(`{%s}`, strings.ToLower(role))
	_, err = db.Exec(r.Context(), updateQuery,
		path,
		action,
		role,
		memberID,
		coterieID,
	)
	if err != nil {
		http.Error(w, "Failed to update roles", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": fmt.Sprintf("Member %s %sd to %s", memberName, action, role),
	})
}

func RemovePostFromCoterie(w http.ResponseWriter, r *http.Request) {
	db := r.Context().Value(database.DBContextKey).(*pgxpool.Pool)

	coterieName := r.URL.Query().Get("coterie")
	postID := r.URL.Query().Get("postID")
	encrypteduserId := r.Header.Get("X-userID")
	if encrypteduserId == "" {
		http.Error(w, "userId query parameter is required", http.StatusBadRequest)
		return
	}

	modID, err := middlewares.DecryptAES(encrypteduserId)
	if err != nil {
		http.Error(w, "Failed to decrypt userid", http.StatusBadRequest)
		return
	}

	var coterieID uuid.UUID
	var ownerID uuid.UUID
	err = db.QueryRow(r.Context(),
		`SELECT id, owner FROM coterie WHERE name = $1`,
		coterieName,
	).Scan(&coterieID, &ownerID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			http.Error(w, "Coterie not found", http.StatusNotFound)
		} else {
			http.Error(w, "Database error", http.StatusInternalServerError)
		}
		return
	}

	var postCoterie string
	err = db.QueryRow(r.Context(),
		`SELECT coterie FROM post WHERE id = $1`,
		postID,
	).Scan(&postCoterie)
	if err != nil {
		http.Error(w, "Post not found", http.StatusNotFound)
		return
	}

	if postCoterie != coterieName {
		http.Error(w, "Post doesn't belong to coterie", http.StatusBadRequest)
		return
	}

	modUUID, err := uuid.Parse(modID)
	if err != nil {
		http.Error(w, "Invalid moderator ID", http.StatusBadRequest)
		return
	}
	isAuthorized := modUUID == ownerID
	if !isAuthorized {
		var rolesJson pgtype.Text
		err := db.QueryRow(r.Context(),
			`SELECT roles FROM coterie WHERE id = $1`,
			coterieID,
		).Scan(&rolesJson)
		if err != nil {
			http.Error(w, "Error checking roles", http.StatusInternalServerError)
			return
		}

		var roles map[string][]uuid.UUID
		if rolesJson.Status == pgtype.Present {
			json.Unmarshal([]byte(rolesJson.String), &roles)
			modUUID, err := uuid.Parse(modID)
			if err != nil {
				http.Error(w, "Invalid moderator ID", http.StatusBadRequest)
				return
			}
			isAuthorized = containsUUID(roles["moderators"], modUUID) ||
				containsUUID(roles["admins"], modUUID)
		}
	}

	if !isAuthorized {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	_, err = db.Exec(r.Context(),
		`DELETE FROM post WHERE id = $1`,
		postID,
	)
	if err != nil {
		http.Error(w, "Failed to delete post", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Post removed"})
}

func BanUser(w http.ResponseWriter, r *http.Request) {
	// Get pgx connection pool from context
	db := r.Context().Value(database.DBContextKey).(*pgxpool.Pool)

	coterieName := r.URL.Query().Get("CoterieName")
	username := r.URL.Query().Get("username")

	// Get moderator ID from context
	encrypteduserId := r.Header.Get("X-userID")
	if encrypteduserId == "" {
		http.Error(w, "userId query parameter is required", http.StatusBadRequest)
		return
	}

	modID, err := middlewares.DecryptAES(encrypteduserId)
	if err != nil {
		http.Error(w, "Failed to decrypt userid", http.StatusBadRequest)
		return
	}

	// Verify moderator exists (redundant check from original code)
	var modIDDB uuid.UUID
	err = db.QueryRow(r.Context(),
		`SELECT id FROM users WHERE id = $1`,
		modID,
	).Scan(&modIDDB)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			http.Error(w, "Moderator not found", http.StatusNotFound)
		} else {
			http.Error(w, "Database error", http.StatusInternalServerError)
		}
		return
	}

	// Get user to ban
	var userID uuid.UUID
	err = db.QueryRow(r.Context(),
		`SELECT id FROM users WHERE username = $1`,
		username,
	).Scan(&userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			http.Error(w, "User not found", http.StatusNotFound)
		} else {
			http.Error(w, "Database error", http.StatusInternalServerError)
		}
		return
	}

	// Check membership
	var isMember bool
	err = db.QueryRow(r.Context(),
		`SELECT EXISTS(
					SELECT 1 FROM coterie 
					WHERE name = $1 AND $2 = ANY(members)
			)`,
		coterieName, userID,
	).Scan(&isMember)
	if err != nil || !isMember {
		http.Error(w, "User is not a coterie member", http.StatusBadRequest)
		return
	}

	// Use transaction for atomic updates
	tx, err := db.Begin(r.Context())
	if err != nil {
		http.Error(w, "Transaction failed", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback(r.Context())

	// Update coterie arrays
	_, err = tx.Exec(r.Context(),
		`UPDATE coterie 
        SET bannedmembers = array_append(bannedmembers, $1),
            members = array_remove(members, $1)
        WHERE name = $2`,
		userID, coterieName,
	)
	if err != nil {
		http.Error(w, "Failed to update coterie", http.StatusInternalServerError)
		return
	}

	if err != nil {
		http.Error(w, "Failed to ban user", http.StatusInternalServerError)
		return
	}

	// Commit transaction
	if err := tx.Commit(r.Context()); err != nil {
		http.Error(w, "Commit failed", http.StatusInternalServerError)
		return
	}

	// Respond with UUID string representation
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": fmt.Sprintf(
			"User '%s' banned from '%s' by moderator '%s'",
			username,
			coterieName,
			modID,
		),
	})
}

func GetCoteriesByUserID(w http.ResponseWriter, r *http.Request) {
	db := r.Context().Value(database.DBContextKey).(*pgxpool.Pool)
	username := chi.URLParam(r, "userParam")
	userIDHeader := r.Header.Get("X-userID")

	var userID uuid.UUID
	var err error

	if userIDHeader != "" {
		userID, err = uuid.Parse(userIDHeader)
		if err != nil {
			http.Error(w, "Invalid user ID", http.StatusBadRequest)
			return
		}
	} else {
		err = db.QueryRow(r.Context(),
			`SELECT id FROM users WHERE username = $1`,
			username,
		).Scan(&userID)
		if err != nil {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}
	}

	rows, err := db.Query(r.Context(),
		`SELECT id, name, avatar, banner, isVerified, 
							isChatAllowed, isOrganisation, roles, members, owner
			 FROM coterie
			 WHERE $1 = ANY(members)`,
		userID,
	)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	coteries := make([]map[string]interface{}, 0)
	for rows.Next() {
		var coterie types.Coterie
		var rolesJson []byte
		var members []uuid.UUID

		err := rows.Scan(
			&coterie.ID,
			&coterie.Name,
			&coterie.Avatar,
			&coterie.Banner,
			&coterie.IsVerified,
			&coterie.IsChatAllowed,
			&coterie.IsOrganisation,
			&rolesJson,
			pq.Array(&members),
			&coterie.Owner,
		)
		if err != nil {
			http.Error(w, "Scan error", http.StatusInternalServerError)
			return
		}

		roles := make(map[string][]uuid.UUID)
		if len(rolesJson) > 0 {
			json.Unmarshal(rolesJson, &roles)
		}

		var postCount int
		err = db.QueryRow(r.Context(),
			`SELECT COUNT(*) FROM post WHERE coterie = $1`,
			coterie.Name,
		).Scan(&postCount)
		if err != nil {
			http.Error(w, "Post count error", http.StatusInternalServerError)
			return
		}

		coteries = append(coteries, map[string]interface{}{
			"name":           coterie.Name,
			"avatar":         coterie.Avatar,
			"banner":         coterie.Banner,
			"isVerified":     coterie.IsVerified,
			"isChatAllowed":  coterie.IsChatAllowed,
			"PostsCount":     postCount,
			"isOwner":        userID == uuid.MustParse(coterie.Owner),
			"isOrganisation": coterie.IsOrganisation,
			"isAdmin":        containsUUID(roles["admins"], userID),
			"TotalMembers":   len(members),
			"isModerator":    containsUUID(roles["moderators"], userID),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(coteries)
}

// Helper function
func containsUUID(slice []uuid.UUID, item uuid.UUID) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// Helper function to check if userID exists in a given list
func contains(list []string, userID string) bool {
	for _, id := range list {
		if id == userID {
			return true
		}
	}
	return false
}

func CoterieRoutes(r chi.Router) {
	r.Get("/coterie/@all", GetAllCoterie)
	r.With(RateLimit(5, 5*time.Minute)).Post("/coterie/membership", CoterieMembership)
	r.With(RateLimit(5, 5*time.Minute)).Post("/coterie/set-warning-limit", SetWarningLimit)
	r.Get("/coterie/{name}", GetCoterieByName)
	r.Get("/user/{userParam}/coteries", GetCoteriesByUserID)
	r.With(RateLimit(5, 5*time.Minute)).Delete("/coterie/remove-post", RemovePostFromCoterie)
	r.With(RateLimit(5, 5*time.Minute)).Post("/coterie/update", UpdateCoterie)
	r.With(RateLimit(5, 5*time.Minute)).Post("/coterie/promote", PromoteMember)
	r.With(RateLimit(5, 5*time.Minute)).Post("/coterie/ban", BanUser)
	r.With(RateLimit(5, 5*time.Minute)).Post("/coterie/warn", WarnMember)
	r.With(RateLimit(1, 20*time.Minute)).Post("/coterie/new", AddNewCoterie)
}
