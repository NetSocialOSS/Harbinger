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
			Port:           "8080",
			ImageUploadKey: "d6b358da96fd1e63b3eadc17fbae7bdb",
		},
	}
}

func GetConfig() types.Config {
	return getConfig()
}
