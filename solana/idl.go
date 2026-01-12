package solana

import "encoding/json"

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

const IDL_JSON = `{
  "address": "B85X9aTrpWAdi1xhLvPmDPuYmfz5YdMd9X8qr7uU4H18",
  "metadata": {
    "name": "arkham_protocol",
    "version": "0.1.0",
    "spec": "0.1.0",
    "description": "Created with Anchor"
  }
}`
