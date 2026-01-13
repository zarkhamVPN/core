package solana

import (
	_ "embed"
	"encoding/json"
)

//go:embed arkham_protocol.json
var IDL_JSON []byte

type IDL struct {
	Address      string `json:"address"`
	Metadata     struct {
		Name        string `json:"name"`
		Version     string `json:"version"`
		Spec        string `json:"spec"`
		Description string `json:"description"`
	} `json:"metadata"`
	Instructions []struct {
		Name          string   `json:"name"`
		Discriminator []uint8  `json:"discriminator"`
		Accounts      []struct {
			Name     string `json:"name"`
			Writable bool   `json:"writable,omitempty"`
			Signer   bool   `json:"signer,omitempty"`
		} `json:"accounts"`
		Args []struct {
			Name string      `json:"name"`
			Type interface{} `json:"type"`
		} `json:"args"`
	} `json:"instructions"`
	Accounts []struct {
		Name          string `json:"name"`
		Discriminator []uint8 `json:"discriminator"`
	} `json:"accounts"`
	Events []struct {
		Name          string `json:"name"`
		Discriminator []uint8 `json:"discriminator"`
	} `json:"events"`
}

func ParseIDL(data []byte) (*IDL, error) {
	var idl IDL
	err := json.Unmarshal(data, &idl)
	return &idl, err
}