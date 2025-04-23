package main

import (
	"fmt"
)

type DatabaseConfig struct {
	ConnectionString string
}

type ServiceConfig struct {
	Host string
	Port string
}

type Config struct {
	Database    *DatabaseConfig
	Service     *ServiceConfig
	Environment string
}

func (sc ServiceConfig) Address() string {
	return fmt.Sprintf("%s:%s", sc.Host, sc.Port)
}
