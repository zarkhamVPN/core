package solana

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	bin "github.com/gagliardetto/binary"
	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"
)

var (
	initIdlOnce  sync.Once
	initIdlErr   error
	idlData      *IDL
	eventNameMap map[[8]byte]string
)

// initializeIDL loads and parses the IDL data once
func initializeIDL() error {
	initIdlOnce.Do(func() {
		idlData, initIdlErr = ParseIDL([]byte(IDL_JSON))
		if initIdlErr != nil {
			return
		}

		eventNameMap = make(map[[8]byte]string)
		for _, event := range idlData.Events {
			var disc [8]byte
			copy(disc[:], event.Discriminator)
			eventNameMap[disc] = event.Name
		}
	})
	return initIdlErr
}

// GetHistory fetches and parses the transaction history for a given public key.
func (c *Client) GetHistory(publicKey solana.PublicKey) (*HistoryResult, error) {
	if err := initializeIDL(); err != nil {
		return nil, fmt.Errorf("failed to initialize IDL: %w", err)
	}

	result := &HistoryResult{
		SolHistory:        make([]GenericEvent, 0),
		ArkhamHistory:     make([]GenericEvent, 0),
		ConnectionHistory: make([]ConnectionEvent, 0),
		ThroughputHistory: make([]GenericEvent, 0),
	}

	ctx := context.Background()

	// Step 1: Get all signatures to process
	allSignatures, err := c.gatherAllRelevantSignatures(ctx, publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to gather signatures: %w", err)
	}

	if len(allSignatures) == 0 {
		return result, nil
	}

	// Step 2: Process transactions concurrently
	var mu sync.Mutex
	var wg sync.WaitGroup

	batchSize := 10
	for i := 0; i < len(allSignatures); i += batchSize {
		end := i + batchSize
		if end > len(allSignatures) {
			end = len(allSignatures)
		}

		for j := i; j < end; j++ {
			wg.Add(1)
			go func(sig solana.Signature) {
				defer wg.Done()

				version := uint64(0)
				tx, err := c.RpcClient.GetTransaction(
					ctx,
					sig,
					&rpc.GetTransactionOpts{
						Encoding:                       solana.EncodingBase64,
						Commitment:                     rpc.CommitmentConfirmed,
						MaxSupportedTransactionVersion: &version,
					},
				)
				if err != nil {
					// fmt.Printf("Warning: failed to fetch transaction %s: %v\n", sig, err)
					return
				}

				parseTransactionForHistory(tx, publicKey, result, &mu)
			}(allSignatures[j])
		}

		wg.Wait()
	}

	return result, nil
}

// gatherAllRelevantSignatures collects signatures from both the user's wallet
// and all related Connection accounts (where user is seeker or warden).
func (c *Client) gatherAllRelevantSignatures(ctx context.Context, publicKey solana.PublicKey) ([]solana.Signature, error) {
	signatureSet := make(map[solana.Signature]bool)
	limit := 1000

	// 1. Get signatures for the user's main wallet
	userSigs, err := c.RpcClient.GetSignaturesForAddressWithOpts(
		ctx,
		publicKey,
		&rpc.GetSignaturesForAddressOpts{
			Limit:      &limit,
			Commitment: rpc.CommitmentConfirmed,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch user signatures: %w", err)
	}

	for _, sigInfo := range userSigs {
		signatureSet[sigInfo.Signature] = true
	}

	// 2. Get the user's PDA (try both seeker and warden)
	seekerPDA, _, _ := GetSeekerPDA(publicKey)
	wardenPDA, _, _ := GetWardenPDAForAuthority(publicKey)

	// Get signatures for the seeker PDA, as they are a mutable account in bandwidth proofs
	if seekerPDA != (solana.PublicKey{}) {
		seekerPdaSigs, err := c.RpcClient.GetSignaturesForAddressWithOpts(
			ctx,
			seekerPDA,
			&rpc.GetSignaturesForAddressOpts{
				Limit:      &limit,
				Commitment: rpc.CommitmentConfirmed,
			},
		)
		if err == nil {
			for _, sigInfo := range seekerPdaSigs {
				signatureSet[sigInfo.Signature] = true
			}
		}
	}

	// 3. Fetch all Connection accounts from the program
	connections, err := c.fetchAllConnections(ctx)
	if err == nil {
		// 4. Filter connections where user is involved
		relevantConnectionPDAs := []solana.PublicKey{}
		for pubkey, conn := range connections {
			if conn.Seeker == seekerPDA || conn.Warden == wardenPDA {
				relevantConnectionPDAs = append(relevantConnectionPDAs, pubkey)
			}
		}

		// 5. Get signatures for each relevant Connection PDA
		for _, connPDA := range relevantConnectionPDAs {
			connSigs, err := c.RpcClient.GetSignaturesForAddressWithOpts(
				ctx,
				connPDA,
				&rpc.GetSignaturesForAddressOpts{
					Limit:      &limit,
					Commitment: rpc.CommitmentConfirmed,
				},
			)
			if err != nil {
				continue
			}

			for _, sigInfo := range connSigs {
				signatureSet[sigInfo.Signature] = true
			}
		}
	}

	return mapKeysToSlice(signatureSet), nil
}

// fetchAllConnections retrieves all Connection accounts from the program.
func (c *Client) fetchAllConnections(ctx context.Context) (map[solana.PublicKey]*Connection, error) {
	resp, err := c.RpcClient.GetProgramAccountsWithOpts(
		ctx,
		ProgramID,
		&rpc.GetProgramAccountsOpts{
			Commitment: rpc.CommitmentConfirmed,
			Filters: []rpc.RPCFilter{
				{
					Memcmp: &rpc.RPCFilterMemcmp{
						Offset: 0,
						Bytes:  Account_Connection[:],
					},
				},
			},
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get program accounts: %w", err)
	}

	connections := make(map[solana.PublicKey]*Connection)
	for _, item := range resp {
		conn, err := ParseAccount_Connection(item.Account.Data.GetBinary())
		if err != nil {
			continue
		}
		connections[item.Pubkey] = conn
	}

	return connections, nil
}

// Helper function to convert map keys to slice
func mapKeysToSlice(m map[solana.Signature]bool) []solana.Signature {
	keys := make([]solana.Signature, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// parseTransactionForHistory parses transaction data to build history
func parseTransactionForHistory(tx *rpc.GetTransactionResult, self solana.PublicKey, result *HistoryResult, mu *sync.Mutex) {
	if tx == nil || tx.Meta == nil {
		return
	}

	var timestamp time.Time
	if tx.BlockTime != nil {
		timestamp = tx.BlockTime.Time()
	} else {
		timestamp = time.Now()
	}

	var signature solana.Signature
	if parsed, err := tx.Transaction.GetTransaction(); err == nil && len(parsed.Signatures) > 0 {
		signature = parsed.Signatures[0]
	}

	if tx.Meta.LogMessages != nil {
		parseArkhamEvents(tx, self, timestamp, signature, result, mu)
	}

	if tx.Transaction != nil {
		parseSolTransfers(tx, self, timestamp, signature, result, mu)
	}

	parseTokenTransfers(tx, self, timestamp, signature, result, mu)
}

// parseArkhamEvents extracts and parses Arkham protocol events from logs
func parseArkhamEvents(tx *rpc.GetTransactionResult, self solana.PublicKey, timestamp time.Time, signature solana.Signature, result *HistoryResult, mu *sync.Mutex) {
	for _, logMsg := range tx.Meta.LogMessages {
		if !strings.Contains(logMsg, "Program data: ") {
			continue
		}

		parts := strings.Split(logMsg, "Program data: ")
		if len(parts) < 2 {
			continue
		}

		eventDataB64 := strings.TrimSpace(parts[1])
		eventData, err := base64.StdEncoding.DecodeString(eventDataB64)
		if err != nil {
			continue
		}

		if len(eventData) < 8 {
			continue
		}

		var disc [8]byte
		copy(disc[:], eventData[:8])

		eventName, found := eventNameMap[disc]
		if !found {
			continue
		}

		switch eventName {
		case "ConnectionEnded":
			parseConnectionEndedEvent(eventData, timestamp, signature, result, mu)
		case "ConnectionStarted":
			parseConnectionStartedEvent(eventData, self, timestamp, signature, result, mu)
		case "BandwidthProofSubmitted":
			parseBandwidthProofEvent(eventData, self, timestamp, signature, result, mu)
		case "EscrowDeposited":
			parseEscrowDepositedEvent(eventData, self, timestamp, signature, result, mu)
		case "EarningsClaimed":
			parseEarningsClaimedEvent(eventData, self, timestamp, signature, result, mu)
		case "TokensClaimed":
			parseTokensClaimedEvent(eventData, self, timestamp, signature, result, mu)
		case "WardenRegistered":
			parseWardenRegisteredEvent(eventData, self, timestamp, signature, result, mu)
		}
	}
}

func parseConnectionEndedEvent(eventData []byte, timestamp time.Time, signature solana.Signature, result *HistoryResult, mu *sync.Mutex) {
	event, err := ParseEvent_ConnectionEnded(eventData)
	if err != nil {
		return
	}

	connectionEvent := ConnectionEvent{
		Signature: signature,
		Timestamp: timestamp,
		Duration:  0,
		Bandwidth: event.BandwidthConsumed,
		Earnings:  event.TotalPaid,
		Warden:    event.Warden,
		Seeker:    event.Seeker,
	}

	mu.Lock()
	result.ConnectionHistory = append(result.ConnectionHistory, connectionEvent)
	mu.Unlock()
}

func parseConnectionStartedEvent(eventData []byte, self solana.PublicKey, timestamp time.Time, signature solana.Signature, result *HistoryResult, mu *sync.Mutex) {
	event, err := ParseEvent_ConnectionStarted(eventData)
	if err != nil {
		return
	}

	genericEvent := GenericEvent{
		Signature: signature,
		Timestamp: timestamp,
		Type:      "ConnectionStarted",
		Amount:    event.EscrowAmount,
		Sender:    &event.Seeker,
		Recipient: &event.Warden,
	}

	mu.Lock()
	result.ArkhamHistory = append(result.ArkhamHistory, genericEvent)
	mu.Unlock()
}

func parseBandwidthProofEvent(eventData []byte, self solana.PublicKey, timestamp time.Time, signature solana.Signature, result *HistoryResult, mu *sync.Mutex) {
	event, err := ParseEvent_BandwidthProofSubmitted(eventData)
	if err != nil {
		return
	}

	mbConsumed := event.MbConsumed
	genericEvent := GenericEvent{
		Signature:  signature,
		Timestamp:  timestamp,
		Type:       "ThroughputCertificateSubmitted",
		Amount:     event.PaymentAmount,
		MbConsumed: &mbConsumed,
	}

	mu.Lock()
	result.ThroughputHistory = append(result.ThroughputHistory, genericEvent)
	mu.Unlock()
}

func parseEscrowDepositedEvent(eventData []byte, self solana.PublicKey, timestamp time.Time, signature solana.Signature, result *HistoryResult, mu *sync.Mutex) {
	event, err := ParseEvent_EscrowDeposited(eventData)
	if err != nil {
		return
	}

	if event.Authority != self {
		return
	}

	genericEvent := GenericEvent{
		Signature: signature,
		Timestamp: timestamp,
		Type:      "EscrowDeposited",
		Amount:    event.Amount,
		Sender:    &event.Authority,
	}

	mu.Lock()
	result.ArkhamHistory = append(result.ArkhamHistory, genericEvent)
	mu.Unlock()
}

func parseEarningsClaimedEvent(eventData []byte, self solana.PublicKey, timestamp time.Time, signature solana.Signature, result *HistoryResult, mu *sync.Mutex) {
	event, err := ParseEvent_EarningsClaimed(eventData)
	if err != nil {
		return
	}

	if event.Authority != self {
		return
	}

	genericEvent := GenericEvent{
		Signature: signature,
		Timestamp: timestamp,
		Type:      "EarningsClaimed",
		Amount:    event.Amount,
		Recipient: &event.Authority,
	}

	mu.Lock()
	result.ArkhamHistory = append(result.ArkhamHistory, genericEvent)
	mu.Unlock()
}

func parseTokensClaimedEvent(eventData []byte, self solana.PublicKey, timestamp time.Time, signature solana.Signature, result *HistoryResult, mu *sync.Mutex) {
	event, err := ParseEvent_TokensClaimed(eventData)
	if err != nil {
		return
	}

	if event.Authority != self {
		return
	}

	genericEvent := GenericEvent{
		Signature: signature,
		Timestamp: timestamp,
		Type:      "ArkhamTokensClaimed",
		Amount:    event.Amount,
		Recipient: &event.Authority,
	}

	mu.Lock()
	result.ArkhamHistory = append(result.ArkhamHistory, genericEvent)
	mu.Unlock()
}

func parseWardenRegisteredEvent(eventData []byte, self solana.PublicKey, timestamp time.Time, signature solana.Signature, result *HistoryResult, mu *sync.Mutex) {
	event, err := ParseEvent_WardenRegistered(eventData)
	if err != nil {
		return
	}

	if event.Authority != self {
		return
	}

	genericEvent := GenericEvent{
		Signature: signature,
		Timestamp: timestamp,
		Type:      "WardenRegistered",
		Amount:    event.StakeAmount,
		Sender:    &event.Authority,
	}

	mu.Lock()
	result.ArkhamHistory = append(result.ArkhamHistory, genericEvent)
	mu.Unlock()
}

func parseSolTransfers(tx *rpc.GetTransactionResult, self solana.PublicKey, timestamp time.Time, signature solana.Signature, result *HistoryResult, mu *sync.Mutex) {
	if tx.Transaction == nil {
		return
	}

	parsed, err := tx.Transaction.GetTransaction()
	if err != nil {
		return
	}

	for _, instr := range parsed.Message.Instructions {
		programIdx := instr.ProgramIDIndex
		if int(programIdx) >= len(parsed.Message.AccountKeys) {
			continue
		}
		programID := parsed.Message.AccountKeys[programIdx]

		if programID != solana.SystemProgramID {
			continue
		}

		if len(instr.Data) < 4 {
			continue
		}

		decoder := bin.NewBorshDecoder(instr.Data)
		var instrType uint32
		if err := decoder.Decode(&instrType); err != nil {
			continue
		}

		if instrType != 2 {
			continue
		}

		var amount uint64
		if err := decoder.Decode(&amount); err != nil {
			continue
		}

		if len(instr.Accounts) < 2 {
			continue
		}

		fromIdx := instr.Accounts[0]
		toIdx := instr.Accounts[1]

		if int(fromIdx) >= len(parsed.Message.AccountKeys) || int(toIdx) >= len(parsed.Message.AccountKeys) {
			continue
		}

		from := parsed.Message.AccountKeys[fromIdx]
		to := parsed.Message.AccountKeys[toIdx]

		if from != self && to != self {
			continue
		}

		eventType := "SOLTransferSent"
		sender := from
		recipient := to

		if to == self {
			eventType = "SOLTransferReceived"
		}

		genericEvent := GenericEvent{
			Signature: signature,
			Timestamp: timestamp,
			Type:      eventType,
			Amount:    amount,
			Sender:    &sender,
			Recipient: &recipient,
		}

		mu.Lock()
		result.SolHistory = append(result.SolHistory, genericEvent)
		mu.Unlock()
	}
}

func parseTokenTransfers(tx *rpc.GetTransactionResult, self solana.PublicKey, timestamp time.Time, signature solana.Signature, result *HistoryResult, mu *sync.Mutex) {
	if tx.Transaction == nil || tx.Meta == nil {
		return
	}

	parsed, err := tx.Transaction.GetTransaction()
	if err != nil {
		return
	}

	arkhamMintPDA, _, err := solana.FindProgramAddress(
		[][]byte{[]byte("arkham_mint")},
		ProgramID,
	)
	if err != nil {
		return
	}

	if tx.Meta.PreTokenBalances != nil && tx.Meta.PostTokenBalances != nil {
		for _, postBalance := range tx.Meta.PostTokenBalances {
			if postBalance.Mint != arkhamMintPDA {
				continue
			}

			var preAmount uint64 = 0
			for _, preBalance := range tx.Meta.PreTokenBalances {
				if preBalance.AccountIndex == postBalance.AccountIndex {
					if preBalance.UiTokenAmount.Amount != "" {
						fmt.Sscanf(preBalance.UiTokenAmount.Amount, "%d", &preAmount)
					}
					break
				}
			}

			var postAmount uint64 = 0
			if postBalance.UiTokenAmount.Amount != "" {
				fmt.Sscanf(postBalance.UiTokenAmount.Amount, "%d", &postAmount)
			}

			if postAmount == preAmount {
				continue
			}

			accountIdx := postBalance.AccountIndex
			if int(accountIdx) >= len(parsed.Message.AccountKeys) {
				continue
			}

			var amount uint64
			var eventType string

			if postAmount > preAmount {
				amount = postAmount - preAmount
				eventType = "ArkhamTokenReceived"
			} else {
				amount = preAmount - postAmount
				eventType = "ArkhamTokenSent"
			}

			genericEvent := GenericEvent{
				Signature: signature,
				Timestamp: timestamp,
				Type:      eventType,
				Amount:    amount,
			}

			mu.Lock()
			result.ArkhamHistory = append(result.ArkhamHistory, genericEvent)
			mu.Unlock()
		}
	}
}
