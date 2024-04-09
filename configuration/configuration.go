package configuration

import (
	"os"

	"netsocial/types"
)

func getConfig() types.Config {
	return types.Config{
		ApiVersion: 5,
		Database: types.Database{
			Url: os.Getenv("DATABASE_URL"),
		},
		Web: types.Web{
			Port:      "8080",
			ReturnUrl: "http://localhost:3000",
		},
	}
}

func GetConfig() types.Config {
	return getConfig()
}
