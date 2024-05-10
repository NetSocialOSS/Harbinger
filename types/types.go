package types

import "time"

type Post struct {
	Avatar      string    `json:"avatar"`
	Text        string    `json:"text"`
	Like        int64     `json:"likes"`
	DisplayName string    `json:"displayname"`
	CreatedAt   time.Time `json:"createdAt"`
}

type Reply struct {
	Avatar      string    `json:"avatar"`
	DisplayName string    `json:"displayname"`
	Text        string    `json:"text"`
	Likes       int64     `json:"likes"`
	CreatedAt   time.Time `json:"createdAt"`
}

type User struct {
	Email       string    `json:"email"`
	DisplayName string    `json:"displayname"`
	UserName    string    `json:"username"`
	Followers   int64     `json:"followers"`
	Following   int64     `json:"following"`
	Bio         string    `json:"bio"`
	Banner      string    `json:"banner"`
	CreatedAt   time.Time `json:"createdAt"`
	Avatar      string    `json:"avatar"`
	Post        []Post    `json:"posts"`
	Reply       []Reply   `json:"replies"`
}

type BlogPost struct {
	Slug        string      `json:"slug"`
	Title       string      `json:"title"`
	Date        string      `json:"date"`
	Author      string      `json:"author"`
	IsCoAuthor  bool        `json:"isCoAuthor"`
	Excerpt     string      `json:"excerpt"`
	Avatar      string      `json:"avatar"`
	Description string      `json:"description,omitempty"`
	CoWriter    bool        `json:"cowriter,omitempty"`
	Content     []PostEntry `json:"content"`
}

type PostEntry struct {
	Heading string `json:"heading"`
	Body    string `json:"body"`
}

type Partner struct {
	Banner string `json:"banner,omitempty" bson:"banner,omitempty"`
	Logo   string `json:"logo,omitempty" bson:"logo,omitempty"`
	Title  string `json:"title,omitempty" bson:"title,omitempty"`
	Text   string `json:"text,omitempty" bson:"text,omitempty"`
	Link   string `json:"link,omitempty" bson:"link,omitempty"`
}

/*
 * ==========================
 * Configuration Types: not suggested to mess with!!
 * ==========================
 */

type Config struct {
	ApiVersion int `json:"apiVersion"`
	Database   `json:"database"`
	Web        `json:"web"`
	APIUrl     string `json:"apiUrl"`
}

type Database struct {
	Url string `json:"url"`
}

type Web struct {
	Port string `json:"port"`
}
