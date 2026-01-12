package solana

import (
	"time"

	"github.com/gagliardetto/solana-go"
)

// GenericEvent represents a basic transaction event.
type GenericEvent struct {
	Signature  solana.Signature  `json:"signature"`
	Timestamp  time.Time         `json:"timestamp"`
	Type       string            `json:"type"`
	Amount     uint64            `json:"amount,omitempty"`
	Sender     *solana.PublicKey `json:"sender,omitempty"`
	Recipient  *solana.PublicKey `json:"recipient,omitempty"`
	MbConsumed *uint64           `json:"mbConsumed,omitempty"`
}

// ConnectionEvent represents a completed dVPN connection.
type ConnectionEvent struct {
	Signature solana.Signature `json:"signature"`
	Timestamp time.Time        `json:"timestamp"`
	Duration  uint64           `json:"duration"`
	Bandwidth uint64           `json:"bandwidth"`
	Earnings  uint64           `json:"earnings"`
	Warden    solana.PublicKey `json:"warden"`
	Seeker    solana.PublicKey `json:"seeker"`
}

// HistoryResult holds the categorized history.
type HistoryResult struct {
	SolHistory        []GenericEvent    `json:"solHistory"`
	ArkhamHistory     []GenericEvent    `json:"arkhamHistory"`
	ConnectionHistory []ConnectionEvent `json:"connectionHistory"`
	ThroughputHistory []GenericEvent    `json:"throughputHistory"`
}

// ConnectionResult wraps a Connection account with its public key.
type ConnectionResult struct {
	PublicKey solana.PublicKey
	Account   Connection
}
