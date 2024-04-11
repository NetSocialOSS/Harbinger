package types

type Post struct {
	Avatar string `json:"avatar"`
}

type User struct {
	Email    string `json:"email"`
	Username string `json:"username"`
	Post     []Post `json:"post"`
}

type BlogPost struct {
	Slug        string          `json:"slug"`
	Title       string          `json:"title"`
	Date        string          `json:"date"`
	Author      string          `json:"author"`
	IsCoAuthor  bool            `json:"isCoAuthor"`
	Excerpt     string          `json:"excerpt"`
	Avatar      string          `json:"avatar"`
	Description string          `json:"description,omitempty"`
	CoWriter    bool            `json:"cowriter,omitempty"`
	Content     []BlogPostEntry `json:"content"`
}

type BlogPostEntry struct {
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
