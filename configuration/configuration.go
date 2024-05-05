package configuration

import (
	"os"

	"socialflux/types"
)

func getConfig() types.Config {
	return types.Config{
		ApiVersion: 2,
		Database: types.Database{
			Url: os.Getenv("DATABASE_URL"),
		},
		Web: types.Web{
			Port: "7070",
		},
	}
}

func GetConfig() types.Config {
	return getConfig()
}
