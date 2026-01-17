package config

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type AppConfig struct {
	SubmitTC bool `json:"submit_tc"`
}

func LoadOrInit(configDir string) (*AppConfig, error) {
	path := filepath.Join(configDir, "app-config.json")
	
	// Check if exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		// Create default
		cfg := &AppConfig{
			SubmitTC: true,
		}
		if err := Save(configDir, cfg); err != nil {
			return nil, err
		}
		return cfg, nil
	}

	// Load existing
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg AppConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func Save(configDir string, cfg *AppConfig) error {
	path := filepath.Join(configDir, "app-config.json")
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
