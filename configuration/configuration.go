package configuration

import (
	"os"

	"netsocial/types"
)

func getConfig() types.Config {
	return types.Config{
		ApiVersion: "3.0.0",
		Database: types.Database{
			Url: os.Getenv("DATABASE_URL"),
		},
	}
}

func GetConfig() types.Config {
	return getConfig()
}
