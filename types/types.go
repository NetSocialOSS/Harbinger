package types

import (
	"time"

	"github.com/google/uuid"
)

type NotificationType string
type SessionType string
type MessageType string

const (
	NotificationTypeLike    NotificationType = "like"
	NotificationTypeComment NotificationType = "comment"
	NotificationTypeFollow  NotificationType = "follow"
	NotificationTypeMention NotificationType = "mention"
)

const (
	SessionTypeHarbinger     SessionType = "harbinger-generated"
	SessionTypeUserGenerated SessionType = "user-generated"
)

const (
	MessageTypeMessage   MessageType = "message"
	MessageTypeMediaOnly MessageType = "media-only"
	MessageTypeMMS       MessageType = "mms"
)

type Post struct {
	ID            string    `bson:"id" json:"id"`
	Title         string    `bson:"title" json:"title"`
	Content       string    `bson:"content" json:"content"`
	Author        string    `bson:"author" json:"-"`
	CommentNumber int       `bson:"commentNumber" json:"commentNumber"`
	TimeAgo       string    `bson:"timeAgo" json:"timeAgo"`
	ScheduledFor  time.Time `bson:"scheduledFor" json:"scheduledFor"`
	Image         []string  `bson:"image" json:"image"`
	Indexing      bool      `bson:"isIndexed"`
	Hearts        []string  `bson:"hearts" json:"hearts"`
	CreatedAt     time.Time `bson:"createdAt" json:"createdAt"`
	Poll          []Poll    `bson:"poll,omitempty" json:"poll,omitempty"`
	Comments      []Comment `bson:"comments,omitempty" json:"comments,omitempty"`
	Coterie       string    `bson:"coterie,omitempty" json:"coterie,omitempty"`
	AuthorDetails Author    `bson:"authorDetails,omitempty" json:"authorDetails,omitempty"`
}

type Poll struct {
	ID         string    `bson:"id" json:"id"`
	Options    []Options `bson:"options" json:"options"`
	CreatedAt  time.Time `bson:"createdAt" json:"createdAt"`
	TotalVotes int       `bson:"totalVotes" json:"totalVotes"`
	Expiration time.Time `bson:"expiration" json:"expiration"`
}

type Options struct {
	ID        string   `bson:"id" json:"id"`
	Votes     []string `bson:"votes" json:"votes"`
	VoteCount int      `json:"voteCount"`
	Name      string   `bson:"name" json:"name"`
}

type NewPost struct {
	ID           string    `json:"id,omitempty" bson:"id,omitempty"`
	Title        string    `json:"title"`
	Content      string    `json:"content"`
	Indexing     bool      `bson:"isIndexed"`
	Author       string    `json:"author"`
	Image        []string  `json:"image,omitempty"`
	ScheduledFor time.Time `bson:"scheduledFor" json:"scheduledFor"`
	Coterie      string    `json:"coterie"`
	Hearts       []string  `json:"hearts,omitempty"`
	CreatedAt    time.Time `json:"createdAt" bson:"createdAt"`
	Poll         []NewPoll `bson:"poll,omitempty" json:"poll,omitempty"`
	Comments     []string  `json:"comments,omitempty" bson:"comments,omitempty"`
}

type NewPoll struct {
	ID         string       `bson:"id" json:"id"`
	Options    []NewOptions `bson:"options" json:"options"`
	CreatedAt  time.Time    `bson:"createdAt" json:"createdAt"`
	Expiration time.Time    `bson:"expiration" json:"expiration"`
}

type NewOptions struct {
	ID    string   `bson:"id" json:"id"`
	Votes []string `bson:"votes" json:"-"`
	Name  string   `bson:"name" json:"name"`
}

type UserSettingsUpdate struct {
	DisplayName    string   `json:"displayName,omitempty"`
	Bio            string   `json:"bio,omitempty"`
	ProfilePicture string   `json:"profilePicture,omitempty"`
	IsOrganisation *bool    `json:"isOrganisation"`
	ProfileBanner  string   `json:"profileBanner,omitempty"`
	Links          []string `json:"links,omitempty"`
}

type Author struct {
	IsVerified     bool      `json:"isVerified"`
	IsDeveloper    bool      `json:"isDeveloper"`
	IsPrivate      bool      `bson:"isPrivate" json:"isPrivate"`
	IsPartner      bool      `json:"isPartner"`
	ProfilePicture *string   `json:"profilePicture,omitempty"`
	ProfileBanner  *string   `bson:"profilebanner" json:"profilebanner"`
	IsOwner        bool      `json:"isOwner"`
	IsModerator    bool      `json:"isModerator"`
	IsOrganisation bool      `json:"isOrganisation"`
	CreatedAt      time.Time `bson:"createdAt" json:"createdAt"`
	Username       string    `bson:"username" json:"username"`
}

type NewComment struct {
	ID        string    `bson:"ID" json:"ID"`
	Content   string    `bson:"content" json:"Content"`
	Author    string    `bson:"author" json:"Author"`
	CreatedAt time.Time `json:"CreatedAt"`
}

type Comment struct {
	ID             uuid.UUID `json:"ID"`
	Author         string    `json:"Author"`
	Content        string    `json:"Content"`
	CreatedAt      time.Time `json:"CreatedAt"`
	IsVerified     bool      `json:"isVerified"`
	IsOrganisation bool      `json:"isOrganisation"`
	IsModerator    bool      `json:"isModerator"`
	IsPartner      bool      `json:"isPartner"`
	AuthorName     string    `json:"authorName"`
	ProfilePicture string    `json:"profilePicture"`
	TimeAgo        string    `json:"timeAgo"`
	IsOwner        bool      `json:"isOwner"`
	IsDeveloper    bool      `json:"isDeveloper"`
	Replies        []Comment `json:"replies"`
}

type User struct {
	ID                 string    `json:"id"`
	Username           string    `json:"username"`
	DisplayName        string    `json:"displayname"`
	UserID             int       `json:"userid"`
	Email              string    `json:"email"`
	CreatedAt          time.Time `json:"createdAt"`
	ProfilePicture     string    `json:"profilepicture"`
	ProfileBanner      *string   `json:"profilebanner"`
	Bio                *string   `json:"bio"`
	IsVerified         bool      `json:"isVerified"`
	IsOrganisation     bool      `json:"isOrganisation"`
	IsDeveloper        bool      `json:"isDeveloper"`
	IsPartner          bool      `json:"isPartner"`
	TempPasswordExpiry time.Time `json:"tempPasswordExpiry"`
	IsOwner            bool      `json:"isOwner"`
	IsModerator        bool      `json:"isModerator"`
	IsPrivate          bool      `json:"isPrivate"`
	IsPrivateHearts    bool      `json:"isPrivateHearts"`
	IsBanned           bool      `json:"isBanned"`
	Session            []Session `json:"session"`
	Password           string    `json:"-"`
	Links              []string  `json:"links,omitempty"`
	Followers          []string  `json:"followers"`
	Following          []string  `json:"following"`
}

type Notification struct {
	ID        uuid.UUID        `json:"id"`
	UserID    uuid.UUID        `json:"userid"`
	Type      NotificationType `json:"type"`
	Content   *string          `json:"content,omitempty"`
	Link      *string          `json:"link,omitempty"`
	IsRead    bool             `json:"isread"`
	CreatedAt time.Time        `json:"createdat"`
}

type Session struct {
	UserID    uuid.UUID   `json:"user_id"`
	SessionID uuid.UUID   `json:"session_id"`
	Device    string      `json:"device"`
	Type      SessionType `json:"type"`
	StartedAt time.Time   `json:"started_at"`
	ExpiresAt time.Time   `json:"expires_at"`
	Token     string      `json:"token"`
}

type Coterie struct {
	ID             uuid.UUID                  `json:"id"`
	Name           string                     `json:"name"`
	Description    *string                    `json:"description"`
	Members        []string                   `json:"members"`
	Owner          string                     `json:"owner"`
	OwnerUsername  string                     `json:"ownerUsername,omitempty"`
	IsOrganisation bool                       `json:"isOrganisation"`
	CreatedAt      time.Time                  `json:"createdAt"`
	Banner         *string                    `json:"banner,omitempty"`
	Avatar         *string                    `json:"avatar,omitempty"`
	IsChatAllowed  bool                       `json:"isChatAllowed"`
	IsVerified     bool                       `json:"isVerified"`
	TotalPosts     int                        `json:"totalPosts,omitempty"`
	Roles          map[string][]string        `json:"roles,omitempty"`
	BannedMembers  []string                   `json:"bannedMembers,omitempty"`
	MemberDetails  []map[string]interface{}   `json:"memberDetails"`
	WarningDetails map[string][]WarningDetail `json:"warningDetails,omitempty"`
	WarningLimit   int                        `json:"warningLimit"`
}

type Roles struct {
	Owner     []string `json:"owners"`
	Moderator []string `json:"moderators"`
	Admin     []string `json:"admins"`
}

type WarningDetail struct {
	Reason string    `json:"reason"`
	Time   time.Time `json:"time"`
}

type Message struct {
	ID        string      `json:"id"`
	Coterie   string      `json:"coterie"`
	UserID    string      `json:"userID"`
	Content   string      `json:"content"`
	Type      MessageType `json:"type"`
	CreatedAt time.Time   `json:"createdAt"`
}

type BlogPost struct {
	ID       string      `json:"id"`
	Slug     string      `json:"slug"`
	Title    string      `json:"title"`
	Date     string      `json:"date"`
	AuthorID string      `json:"authorId"`
	Overview string      `json:"overview"`
	Content  []PostEntry `json:"content"`
}

type PostEntry struct {
	Body string `json:"body"`
}

type Partner struct {
	ID     string `json:"id"`
	Banner string `json:"banner,omitempty"`
	Logo   string `json:"logo,omitempty"`
	Title  string `json:"title,omitempty"`
	Text   string `json:"text,omitempty"`
	Link   string `json:"link,omitempty"`
}

type LinkPreview struct {
	URL         string   `json:"url"`
	Images      []string `json:"images"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Domain      string   `json:"domain"`
}

/*
 * ==========================
 * Configuration Types: not suggested to mess with!!
 * ==========================
 */

type Config struct {
	PsqlURL          string `yaml:"psqlURL"`
	RedisURL         string `yaml:"redisURL"`
	Port             int    `yaml:"port" default:"8080"`
	AESKey           string `yaml:"aeskey"`
	JwtSecret        string `yaml:"jwtkey"`
	BugReportWebhook string `yaml:"bugreportwebhook"`
	Workers          int    `yaml:"workers" default:"100"`
	ReportWebhook    string `yaml:"reportwebhook"`
	ResendKey        string `yaml:"resendkey"`
	Environment      string `yaml:"environment" default:"development"`
	ApiVersion       string `yaml:"api_version" default:"4.0.0"`
	CsrfKey          string `yaml:"CsrfKey"`
	Algor            Algor  `yaml:"algor"`
	SMTP             SMTP   `yaml:"smtp"`
}

type Algor struct {
	OllamaURL            string        `yaml:"ollama_url" default:"http://localhost:11434"`
	AIRecommenderEnabled bool          `yaml:"ai_recommender_enabled" default:"false"`
	RunModel             bool          `yaml:"run_model" default:"false"`
	ImageFiltering       bool          `yaml:"image_filtering" default:"true"`
	SpamDetection        bool          `yaml:"spam_detection" default:"true"`
	MassMentionDetection bool          `yaml:"mass_mention_detection" default:"true"`
	Models               ModelResponse `json:"models"`
}

type ModelResponse struct {
	Models []struct {
		Name  string `json:"name"`
		Model string `json:"model"`
	} `json:"models"`
}

type SMTP struct {
	Host        string `yaml:"host"`
	Port        int    `yaml:"port"`
	Username    string `yaml:"username"`
	AccessToken string `yaml:"access_token"`
	Password    string `yaml:"password"`
}
