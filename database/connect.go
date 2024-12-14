package database

import (
	"database/sql"

	_ "github.com/lib/pq"
)

func Connect(url string) (*sql.DB, error) {
	db, err := sql.Open("postgres", url)
	if err != nil {
		return nil, err
	}

	err = db.Ping()
	if err != nil {
		db.Close()
		return nil, err
	}

	return db, nil
}

func Disconnect(db *sql.DB) error {
	if err := db.Close(); err != nil {
		return err
	}
	return nil
}
