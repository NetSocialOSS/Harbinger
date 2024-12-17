package routes

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/lib/pq"

	"netsocial/middlewares"
	"netsocial/types"
)

func getUserDetails(db *sql.DB, userID uuid.UUID, cache map[uuid.UUID]map[string]string) (map[string]string, error) {
	if userDetails, exists := cache[userID]; exists {
		return userDetails, nil
	}

	var user types.User
	err := db.QueryRowContext(context.Background(), `SELECT id, username, profilepicture FROM users WHERE id = $1`, userID).Scan(&user.ID, &user.Username, &user.ProfilePicture)
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
	db := r.Context().Value("db").(*sql.DB)

	rows, err := db.Query(`
			SELECT id, name, description, createdat, avatar, banner, members, "isVerified", "isOrganisation"
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
		if err := rows.Scan(&coterie.ID, &coterie.Name, &coterie.Description, &coterie.CreatedAt, &coterie.Avatar, &coterie.Banner, pq.Array(&coterie.Members), &coterie.IsVerified, &coterie.IsOrganisation); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		var postCount int
		err = db.QueryRow(`
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
	db, ok := r.Context().Value("db").(*sql.DB)
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

	err := db.QueryRowContext(context.Background(), `
	SELECT id, name, description, members, owner, createdat, banner, avatar, "isChatAllowed", "isVerified", "isOrganisation", roles, bannedmembers
	FROM coterie WHERE name ILIKE $1
`, coterieName).Scan(
		&coterie.ID,
		&coterie.Name,
		&coterie.Description,
		pq.Array(&coterie.Members),
		&coterie.Owner,
		&coterie.CreatedAt,
		&coterie.Banner,
		&coterie.Avatar,
		&coterie.IsChatAllowed,
		&coterie.IsVerified,
		&coterie.IsOrganisation,
		&rolesJSON,
		pq.Array(&coterie.BannedMembers),
	)

	if err != nil {
		if err == sql.ErrNoRows {
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
	err = db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM post WHERE coterie = $1`, coterie.Name).Scan(&postCount)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	result["TotalPosts"] = postCount

	// Fetch posts if action is "posts" or unspecified
	var posts []map[string]interface{}
	if action == "posts" || action == "" || action == "all" {

		rows, err := db.QueryContext(context.Background(), `
			SELECT id, title, content, author, scheduledfor, image, hearts, createdat, poll, comments
			FROM post WHERE coterie = $1 ORDER BY createdat DESC
		`, coterie.Name)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()
		var scheduledFor pq.NullTime
		var pollJSON *json.RawMessage
		var commentsJSON sql.NullString

		for rows.Next() {
			var post types.Post
			err := rows.Scan(&post.ID, &post.Title, &post.Content, &post.Author, &scheduledFor, pq.Array(&post.Image), pq.Array(&post.Hearts), &post.CreatedAt, &pollJSON, &commentsJSON)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			if commentsJSON.Valid {
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

			if scheduledFor.Valid {
				post.ScheduledFor = scheduledFor.Time
			} else {
				post.ScheduledFor = time.Time{} // Default zero value for time.Time
			}

			var author types.User
			err = db.QueryRowContext(context.Background(), `SELECT id, username, profilepicture, profilebanner, isverified, isorganisation, isdeveloper, ispartner, isowner, ismoderator FROM users WHERE id = $1`, post.Author).Scan(&author.ID, &author.Username, &author.ProfilePicture, &author.ProfileBanner, &author.IsVerified, &author.IsOrganisation, &author.IsDeveloper, &author.IsPartner, &author.IsOwner, &author.IsModerator)
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
			if !post.ScheduledFor.IsZero() && post.ScheduledFor.After(now) {
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
	db := r.Context().Value("db").(*sql.DB)

	title := r.Header.Get("X-name")
	encryptedOwner := r.Header.Get("X-userID")

	// Decrypt the user ID
	owner, err := middlewares.DecryptAES(encryptedOwner)
	if err != nil {
		http.Error(w, "Failed to decrypt userid", http.StatusBadRequest)
		return
	}

	if title == "" {
		http.Error(w, "Coterie name cannot be blank", http.StatusBadRequest)
		return
	}

	var user types.User
	// Ensure the user struct matches the correct type for the database schema
	err = db.QueryRow("SELECT id FROM users WHERE id = $1", owner).Scan(&user.ID) // Assuming 'ID' is a string field
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
	err = db.QueryRow("SELECT name FROM coterie WHERE name = $1", title).Scan(&existingCoterie.Name)
	if err == nil {
		http.Error(w, "A coterie with this name already exists", http.StatusConflict)
		return
	}

	// Insert the new coterie
	_, err = db.Exec(`
			INSERT INTO coterie (id, name, description, members, owner, createdat)
			VALUES ($1, $2, $3, $4, $5, $6)`,
		uuid.New().String(), title, "", pq.Array([]string{owner}), owner, time.Now(),
	)
	if err != nil {
		http.Error(w, "Failed to create coterie: "+err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"id":        uuid.New().String(),
		"name":      title,
		"owner":     owner,
		"createdAt": time.Now(),
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

func CoterieMembership(w http.ResponseWriter, r *http.Request) {
	db := r.Context().Value("db").(*sql.DB)

	coterieName := r.Header.Get("X-name")
	encryptedUserID := r.Header.Get("X-userID")
	action := r.Header.Get("X-action")

	userID, err := middlewares.DecryptAES(encryptedUserID)
	if err != nil {
		http.Error(w, "Failed to decrypt user ID", http.StatusBadRequest)
		return
	}

	// Check if user exists
	var user types.User
	err = db.QueryRow("SELECT username FROM users WHERE id = $1", userID).Scan(&user.Username)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
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
	err = db.QueryRow("SELECT id FROM coterie WHERE name = $1", coterieName).Scan(&coterie.Name)
	if err != nil {
		http.Error(w, "Coterie not found", http.StatusNotFound)
		return
	}

	switch action {
	case "join":
		// Add user to the coterie
		_, err = db.Exec(`
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
		_, err = db.Exec(`
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
	db := r.Context().Value("db").(*sql.DB)

	// Get query parameters
	name := r.URL.Query().Get("name")
	limitStr := r.URL.Query().Get("limitnumber")
	encryptedUserID := r.Header.Get("X-userID")

	// Decrypt and parse the user ID
	ownerIDStr, err := middlewares.DecryptAES(encryptedUserID)
	if err != nil {
		http.Error(w, "Failed to decrypt user ID", http.StatusBadRequest)
		return
	}

	// Convert limit to integer
	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit < 1 || limit > 9 {
		http.Error(w, "Invalid warning limit. Must be between 1 and 9.", http.StatusBadRequest)
		return
	}

	// Parse the owner ID
	ownerID, err := uuid.Parse(ownerIDStr)
	if err != nil {
		http.Error(w, "Invalid OwnerID.", http.StatusBadRequest)
		return
	}

	// Check if the coterie exists and retrieve owner details
	var dbOwnerID string
	var dbWarningLimit int
	err = db.QueryRow(`SELECT owner, warninglimit FROM coterie WHERE name = $1`, name).Scan(&dbOwnerID, &dbWarningLimit)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Coterie not found.", http.StatusNotFound)
		} else {
			http.Error(w, "Error fetching coterie details.", http.StatusInternalServerError)
		}
		return
	}

	// Check if the current user is the owner
	if dbOwnerID != ownerID.String() {
		http.Error(w, "Unauthorized. Only the coterie owner can update the warning limit.", http.StatusUnauthorized)
		return
	}

	// Update the warning limit for the coterie
	_, err = db.Exec(`UPDATE coterie SET warninglimit = $1 WHERE name = $2 AND owner = $3`, limit, name, ownerID.String())
	if err != nil {
		http.Error(w, "Failed to update warning limit.", http.StatusInternalServerError)
		return
	}

	// Send response
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":      "Warning limit updated",
		"warningLimit": limit,
	})
}

// UpdateCoterie function
func UpdateCoterie(w http.ResponseWriter, r *http.Request) {
	// Extract database connection from context
	db := r.Context().Value("db").(*sql.DB)

	// Parse query parameters
	newName := r.URL.Query().Get("newName")
	coterieName := r.URL.Query().Get("name")
	newDescription := r.URL.Query().Get("newDescription")
	newBanner := r.URL.Query().Get("newBanner")
	newAvatar := r.URL.Query().Get("newAvatar")
	isChatAllowedStr := r.URL.Query().Get("isChatAllowed")
	encryptedUserID := r.Header.Get("X-userID")

	// Decrypt and parse the user ID
	ownerID, err := middlewares.DecryptAES(encryptedUserID)
	if err != nil {
		http.Error(w, "Failed to decrypt user ID", http.StatusBadRequest)
		return
	}

	ownerUUID, err := uuid.Parse(ownerID)
	if err != nil {
		http.Error(w, "Invalid owner ID", http.StatusBadRequest)
		return
	}

	// Build dynamic SQL update query
	updateFields := []string{}
	updateValues := []interface{}{}

	// Dynamically construct the SQL update fields and parameters
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
		updateFields = append(updateFields, fmt.Sprintf("\"isChatAllowed\" = $%d", index))
		updateValues = append(updateValues, isChatAllowed)
		index++
	}

	if len(updateFields) == 0 {
		http.Error(w, "No fields to update", http.StatusBadRequest)
		return
	}

	// Construct the final query
	query := fmt.Sprintf(`
			UPDATE coterie
			SET %s
			WHERE LOWER(name) = LOWER($%d) AND owner = $%d
			RETURNING id, name, description, banner, avatar, "isChatAllowed", owner`,
		strings.Join(updateFields, ", "), index, index+1)

	updateValues = append(updateValues, coterieName, ownerUUID.String())

	// Execute the query
	row := db.QueryRow(query, updateValues...)

	// Process response and handle errors
	var coterie types.Coterie
	if err := row.Scan(&coterie.ID, &coterie.Name, &coterie.Description, &coterie.Banner, &coterie.Avatar, &coterie.IsChatAllowed, &coterie.Owner); err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Coterie not found or you are not the owner", http.StatusNotFound)
		} else {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	// Respond with success
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
	db := r.Context().Value("db").(*sql.DB)

	coterieName := r.URL.Query().Get("CoterieName")
	membername := r.URL.Query().Get("username")
	encryptedUserID := r.Header.Get("X-userID")
	reason := r.URL.Query().Get("reason")

	// Decrypt and parse the user ID
	modIDStr, err := middlewares.DecryptAES(encryptedUserID)
	if err != nil {
		http.Error(w, "Failed to decrypt user ID", http.StatusBadRequest)
		return
	}

	// Find member
	var member types.User
	err = db.QueryRow(`SELECT id FROM users WHERE username = $1`, membername).Scan(&member.ID)
	if err != nil {
		http.Error(w, "Member not found", http.StatusNotFound)
		return
	}

	// Find coterie and roles
	var coterie types.Coterie
	var warningDetailsJson []byte
	var owner string
	var rolesText sql.NullString
	err = db.QueryRow(`
		SELECT id, members, warningDetails, roles, owner
		FROM coterie WHERE name = $1
	`, coterieName).Scan(&coterie.ID, pq.Array(&coterie.Members), &warningDetailsJson, &rolesText, &owner)
	if err != nil {
		http.Error(w, "Coterie not found", http.StatusNotFound)
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

	roles := []string{}
	if rolesText.Valid {
		roles = append([]string{owner}, strings.Split(rolesText.String, ",")...)
	} else {
		roles = []string{owner}
	}

	for _, role := range roles {
		if role == modIDStr {
			isAuthorized = true
			break
		}
	}

	if !isAuthorized {
		http.Error(w, "Unauthorized. Only owners, admins, or moderators can warn members.", http.StatusUnauthorized)
		return
	}

	_, err = db.Exec(`
	UPDATE coterie
	SET warningDetails = jsonb_set(
			warningDetails,
			array[$1],
			jsonb_build_object('reason', $2::text, 'time', $3::timestamp)
	)
	WHERE name = $4`,
		member.UserID, reason, time.Now().Format(time.RFC3339), coterieName)

	if err != nil {
		http.Error(w, "Failed to warn member", http.StatusInternalServerError)
		return
	}

	// Send response
	json.NewEncoder(w).Encode(map[string]string{
		"message": fmt.Sprintf("Member %s successfully warned for reason: %s", membername, reason),
	})
}

func PromoteMember(w http.ResponseWriter, r *http.Request) {
	db, ok := r.Context().Value("db").(*sql.DB)
	if !ok {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	coterieName := r.URL.Query().Get("CoterieName")
	role := r.URL.Query().Get("role")
	memberName := r.URL.Query().Get("username")
	encryptedUserID := r.Header.Get("X-userID")
	action := r.URL.Query().Get("action")

	// Decrypt user ID
	promoterIDStr, err := middlewares.DecryptAES(encryptedUserID)
	if err != nil {
		http.Error(w, "Failed to decrypt user ID", http.StatusBadRequest)
		return
	}

	promoterID, err := uuid.Parse(promoterIDStr)
	if err != nil {
		http.Error(w, "Invalid PromoterID", http.StatusBadRequest)
		return
	}

	var memberID string
	err = db.QueryRow(`SELECT id FROM users WHERE username = $1`, memberName).Scan(&memberID)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Member not found", http.StatusNotFound)
			return
		}
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	var coterieID, ownerID string
	var rolesJson sql.NullString
	err = db.QueryRow(`SELECT id, owner, roles FROM coterie WHERE name = $1`, coterieName).Scan(&coterieID, &ownerID, &rolesJson)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Coterie not found", http.StatusNotFound)
			return
		}
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if ownerID != promoterID.String() {
		http.Error(w, "Only the owner can promote or demote members", http.StatusUnauthorized)
		return
	}

	if role != "Moderator" && role != "Owner" && role != "Admin" {
		http.Error(w, "Invalid role. Must be 'Moderator', 'Admin', or 'Owner'", http.StatusBadRequest)
		return
	}

	if action != "promote" && action != "demote" {
		http.Error(w, "Invalid action. Must be 'promote' or 'demote'", http.StatusBadRequest)
		return
	}

	var updateQuery string
	if action == "promote" {
		updateQuery = `UPDATE coterie
							SET roles = jsonb_set(
								COALESCE(roles, '{}'::jsonb),
								'{` + role + `}',
								COALESCE(roles->'` + role + `', '[]'::jsonb) || to_jsonb($1::text)
							)
							WHERE id = $2`
	} else {
		updateQuery = `UPDATE coterie
							SET roles = jsonb_set(
								COALESCE(roles, '{}'::jsonb),
								'{` + role + `}',
								roles->'` + role + `' - to_jsonb($1::text)
							)
							WHERE id = $2`
	}

	_, err = db.Exec(updateQuery, memberID, coterieID)
	if err != nil {
		http.Error(w, "Failed to update coterie", http.StatusInternalServerError)
		return
	}

	response := map[string]string{
		"message": fmt.Sprintf("Member %s successfully %sd to %s", memberName, action, role),
	}
	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(response)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

func RemovePostFromCoterie(w http.ResponseWriter, r *http.Request) {
	db := r.Context().Value("db").(*sql.DB)

	coterieName := r.URL.Query().Get("coterie")
	postIDStr := r.URL.Query().Get("postID")
	encryptedUserID := r.Header.Get("X-userID")

	modIDStr, err := middlewares.DecryptAES(encryptedUserID)
	if err != nil {
		http.Error(w, "Failed to decrypt user ID", http.StatusBadRequest)
		return
	}

	modID, err := uuid.Parse(modIDStr)
	if err != nil {
		http.Error(w, "Invalid moderator ID", http.StatusBadRequest)
		return
	}

	// Fetch coterie details
	var coterieID, ownerID string
	err = db.QueryRow(`SELECT id, owner FROM coterie WHERE name = $1`, coterieName).Scan(&coterieID, &ownerID)
	if err != nil {
		http.Error(w, "Coterie not found", http.StatusNotFound)
		return
	}

	// Fetch post details
	var postCoterie string
	err = db.QueryRow(`SELECT coterie FROM post WHERE id = $1`, postIDStr).Scan(&postCoterie)
	if err != nil {
		http.Error(w, "Post not found", http.StatusNotFound)
		return
	}

	if postCoterie != coterieName {
		http.Error(w, "Post does not belong to the specified coterie", http.StatusBadRequest)
		return
	}

	// Check if the user is an authorized moderator or owner
	var isAuthorized bool
	if modID.String() == ownerID {
		isAuthorized = true
	} else {
		var roleJson string
		err = db.QueryRow(`SELECT roles FROM coterie WHERE id = $1`, coterieID).Scan(&roleJson)
		if err != nil {
			http.Error(w, "Error fetching roles", http.StatusInternalServerError)
			return
		}

		// Check for moderator role
		var roles map[string][]string
		json.Unmarshal([]byte(roleJson), &roles)
		if contains(roles["moderators"], modID.String()) || contains(roles["admins"], modID.String()) {
			isAuthorized = true
		}
	}

	if !isAuthorized {
		http.Error(w, "Unauthorized. Only owners, admins, or moderators can remove posts.", http.StatusUnauthorized)
		return
	}

	// Remove the post from the posts table
	_, err = db.Exec(`DELETE FROM post WHERE id = $1`, postIDStr)
	if err != nil {
		http.Error(w, "Error removing post", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"message": "Post removed successfully"}`))
}

func BanUser(w http.ResponseWriter, r *http.Request) {
	db := r.Context().Value("db").(*sql.DB)

	coterieName := r.URL.Query().Get("CoterieName")
	username := r.URL.Query().Get("username")
	encryptedUserID := r.Header.Get("X-userID")

	// Decrypt the moderator ID
	modID, err := middlewares.DecryptAES(encryptedUserID)
	if err != nil {
		http.Error(w, "Failed to decrypt user ID", http.StatusBadRequest)
		return
	}

	// Get the moderator ID
	var modIDStr string
	err = db.QueryRow(`SELECT id FROM users WHERE id = $1`, modID).Scan(&modIDStr)
	if err != nil {
		http.Error(w, "Moderator not found", http.StatusNotFound)
		return
	}

	// Get the user ID to ban
	var userID string
	err = db.QueryRow(`SELECT id FROM users WHERE username = $1`, username).Scan(&userID)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Check if the user is a member of the coterie
	var isMember bool
	err = db.QueryRow(`SELECT EXISTS(SELECT 1 FROM coterie WHERE name = $1 AND $2 = ANY(members))`, coterieName, userID).Scan(&isMember)
	if err != nil || !isMember {
		http.Error(w, "User is not a member of this coterie", http.StatusBadRequest)
		return
	}

	// Add user to bannedMembers array in coterie table
	_, err = db.Exec(`UPDATE coterie SET bannedmembers = array_append(bannedmembers, $1) WHERE name = $2`, userID, coterieName)
	if err != nil {
		http.Error(w, "Error banning user from coterie", http.StatusInternalServerError)
		return
	}

	// Remove user from members array in coterie table
	_, err = db.Exec(`UPDATE coterie SET members = array_remove(members, $1) WHERE name = $2`, userID, coterieName)
	if err != nil {
		http.Error(w, "Error removing user from coterie members", http.StatusInternalServerError)
		return
	}

	// Mark the user as banned in the users table
	_, err = db.Exec(`UPDATE users SET isbanned = true WHERE id = $1`, userID)
	if err != nil {
		http.Error(w, "Error banning user", http.StatusInternalServerError)
		return
	}

	// Respond to the client
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"message": "User '%s' has been banned from coterie '%s' by moderator '%s'"}`, username, coterieName, modIDStr)
}

func GetCoteriesByUserID(w http.ResponseWriter, r *http.Request) {
	// Retrieve the PostgreSQL database connection from the context
	db, ok := r.Context().Value("db").(*sql.DB)
	if !ok {
		http.Error(w, "Database connection not available", http.StatusInternalServerError)
		return
	}

	// Retrieve the username from the URL parameter
	username := chi.URLParam(r, "userParam")

	// Retrieve the user ID from the request header
	userIDHeader := r.Header.Get("X-userID")

	var userID string
	var err error

	// If the user ID is passed in the header, use it
	if userIDHeader != "" {
		userID = userIDHeader
	} else {
		// Otherwise, treat the parameter as a username and fetch the user ID
		query := `SELECT id FROM users WHERE username = $1`
		row := db.QueryRowContext(r.Context(), query, username)

		err := row.Scan(&userID)
		if err != nil {
			if err == sql.ErrNoRows {
				http.Error(w, "User not found", http.StatusNotFound)
			} else {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			return
		}
	}

	// Fetch the coteries by user ID
	query := `
		SELECT c.id, c.name, c.avatar, c.banner, c."isVerified", c."isChatAllowed", c."isOrganisation", c.roles, c.members, c.owner
		FROM coterie c
		WHERE $1 = ANY(c.members)`
	rows, err := db.QueryContext(r.Context(), query, userID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var coteries []map[string]interface{}
	for rows.Next() {
		var coterie types.Coterie
		var rolesJSON []byte

		err := rows.Scan(&coterie.ID, &coterie.Name, &coterie.Avatar, &coterie.Banner, &coterie.IsVerified, &coterie.IsChatAllowed, &coterie.IsOrganisation, &rolesJSON, pq.Array(&coterie.Members), &coterie.Owner)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Check if rolesJSON is not empty and unmarshal it
		var roles map[string][]string
		if len(rolesJSON) > 0 {
			err = json.Unmarshal(rolesJSON, &roles)
			if err != nil {
				http.Error(w, "Failed to unmarshal roles", http.StatusInternalServerError)
				return
			}
		} else {
			// Default empty map if roles are not provided
			roles = make(map[string][]string)
		}
		coterie.Roles = roles

		// Handle nullable fields like banner
		isOwner := userID == coterie.Owner
		isAdmin := contains(coterie.Roles["admins"], userID)
		isModerator := contains(coterie.Roles["moderators"], userID)

		// Get post count
		var postCount int
		postCountQuery := `SELECT COUNT(*) FROM post WHERE coterie = $1`
		err = db.QueryRowContext(r.Context(), postCountQuery, coterie.Name).Scan(&postCount)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Append coterie info
		coteries = append(coteries, map[string]interface{}{
			"name":           coterie.Name,
			"avatar":         coterie.Avatar,
			"banner":         coterie.Banner,
			"isVerified":     coterie.IsVerified,
			"isChatAllowed":  coterie.IsChatAllowed,
			"PostsCount":     postCount,
			"isOwner":        isOwner,
			"isOrganisation": coterie.IsOrganisation,
			"isAdmin":        isAdmin,
			"TotalMembers":   len(coterie.Members),
			"isModerator":    isModerator,
		})
	}

	if err := rows.Err(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Return the list of coteries as JSON
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(coteries); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
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
	r.With(RateLimit(5, 5*time.Minute)).Post("/coterie/membership", (middlewares.DiscordErrorReport(http.HandlerFunc(CoterieMembership)).ServeHTTP))
	r.With(RateLimit(5, 5*time.Minute)).Post("/coterie/set-warning-limit", (middlewares.DiscordErrorReport(http.HandlerFunc(SetWarningLimit)).ServeHTTP))
	r.Get("/coterie/{name}", GetCoterieByName)
	r.Get("/user/{userParam}/coteries", GetCoteriesByUserID)
	r.With(RateLimit(5, 5*time.Minute)).Delete("/coterie/remove-post", (middlewares.DiscordErrorReport(http.HandlerFunc(RemovePostFromCoterie)).ServeHTTP))
	r.With(RateLimit(5, 5*time.Minute)).Post("/coterie/update", (middlewares.DiscordErrorReport(http.HandlerFunc(UpdateCoterie)).ServeHTTP))
	r.With(RateLimit(5, 5*time.Minute)).Post("/coterie/promote", (middlewares.DiscordErrorReport(http.HandlerFunc(PromoteMember)).ServeHTTP))
	r.With(RateLimit(5, 5*time.Minute)).Post("/coterie/ban", (middlewares.DiscordErrorReport(http.HandlerFunc(BanUser)).ServeHTTP))
	r.With(RateLimit(5, 5*time.Minute)).Post("/coterie/warn", (middlewares.DiscordErrorReport(http.HandlerFunc(WarnMember)).ServeHTTP))
	r.With(RateLimit(1, 20*time.Minute)).Post("/coterie/new", (middlewares.DiscordErrorReport(http.HandlerFunc(AddNewCoterie)).ServeHTTP))
}
