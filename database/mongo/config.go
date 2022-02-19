package mongo

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Config interface {
	Load(configPath string) error
	GetUri() string
	GetDatabase() string
}

func NewConfig() Config {
	return &config{
		MongoDb: mongoDbConfig{
			Uri:      "mongodb://localhost:27017",
			Database: "identity",
		},
	}
}

type config struct {
	MongoDb mongoDbConfig `yaml:"mongodb"`
}

type mongoDbConfig struct {
	Uri      string `yaml:"uri"`
	Database string `yaml:"database"`
}

func (cfg *config) GetUri() string {
	return cfg.MongoDb.Uri
}

func (cfg *config) GetDatabase() string {
	return cfg.MongoDb.Database
}

func (cfg *config) Load(configPath string) error {
	err := cfg.loadYaml(configPath)
	cfg.LoadEnvironment()
	return err
}

func (cfg *config) loadYaml(configPath string) error {
	// Open the config file
	file, err := os.Open(configPath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Read the config file
	decoder := yaml.NewDecoder(file)
	err = decoder.Decode(cfg)
	if err != nil {
		return err
	}

	return nil
}

func (cfg *config) LoadEnvironment() {
	mongo_uri, ok := os.LookupEnv("MONGO_URI")
	if ok && len(mongo_uri) > 0 {
		cfg.MongoDb.Uri = mongo_uri
	}
	mongo_db, ok := os.LookupEnv("MONGO_DB")
	if ok && len(mongo_db) > 0 {
		cfg.MongoDb.Database = mongo_db
	}
}
