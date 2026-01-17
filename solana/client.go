package solana

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/programs/system"
	"github.com/gagliardetto/solana-go/rpc"
	"github.com/gagliardetto/solana-go/rpc/jsonrpc"
	"golang.org/x/crypto/sha3"
)

var AssociatedTokenProgramID = solana.MustPublicKeyFromBase58("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")
var Ed25519ProgramID = solana.MustPublicKeyFromBase58("Ed25519SigVerify111111111111111111111111111")
var ComputeBudgetProgramID = solana.MustPublicKeyFromBase58("ComputeBudget111111111111111111111111111111")

var (
	DevnetUsdcMint = solana.MustPublicKeyFromBase58("4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU")
	DevnetUsdtMint = solana.MustPublicKeyFromBase58("4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU")
)

const ConfigServerURL = "https://api.zarkham.xyz/api/v1/config"

type ConfigResponse struct {
	RpcEndpoint string `json:"rpc_endpoint"`
	BackupRpc   string `json:"backup_rpc"`
}

func FetchRemoteRPCConfig(privKey solana.PrivateKey) (string, error) {
	// 1. Generate Auth Headers
	ts := time.Now().Unix()
	msg := fmt.Sprintf("zarkham-auth-%d", ts)
	
	sig, err := privKey.Sign([]byte(msg))
	if err != nil {
		return "", fmt.Errorf("failed to sign auth message: %w", err)
	}

	req, err := http.NewRequest("GET", ConfigServerURL, nil)
	if err != nil { return "", err }
	
	req.Header.Set("X-Auth-Pubkey", privKey.PublicKey().String())
	req.Header.Set("X-Auth-Sig", sig.String())
	req.Header.Set("X-Auth-Ts", fmt.Sprintf("%d", ts))
	
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil { return "", err }
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("config server error: %d", resp.StatusCode)
	}

	var cfg ConfigResponse
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		return "", err
	}

	return cfg.RpcEndpoint, nil
}

var GlobalClockOffset int64

type SignedTransport struct {
	Transport http.RoundTripper
	PrivKey   solana.PrivateKey
}

func (t *SignedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Only sign requests to our proxy
	if strings.Contains(req.URL.Host, "zarkham") {
		ts := time.Now().Unix() + GlobalClockOffset
		msg := fmt.Sprintf("zarkham-auth-%d", ts)
		
		sig, err := t.PrivKey.Sign([]byte(msg))
		if err != nil {
			return nil, fmt.Errorf("signing failed: %w", err)
		}

		// Also attach as query params for RPC libs that don't support custom headers easily
		q := req.URL.Query()
		q.Add("pubkey", t.PrivKey.PublicKey().String())
		q.Add("sig", sig.String())
		q.Add("ts", fmt.Sprintf("%d", ts))
		req.URL.RawQuery = q.Encode()

		// And headers for good measure
		req.Header.Set("X-Auth-Pubkey", t.PrivKey.PublicKey().String())
		req.Header.Set("X-Auth-Sig", sig.String())
		req.Header.Set("X-Auth-Ts", fmt.Sprintf("%d", ts))
	}

	resp, err := t.Transport.RoundTrip(req)
	if err == nil && resp != nil {
		// Extract Solana Time from header to maintain sync
		if solTimeStr := resp.Header.Get("X-Solana-Time"); solTimeStr != "" {
			if st, parseErr := strconv.ParseInt(solTimeStr, 10, 64); parseErr == nil {
				GlobalClockOffset = st - time.Now().Unix()
			}
		}
	}
	return resp, err
}

var globalSessionWallet *solana.Wallet

func InitGlobalAuth() {
	if globalSessionWallet == nil {
		globalSessionWallet = solana.NewWallet()
		
		// Spawn background time-healing loop
		go func() {
			sc, _ := NewReadOnlyClient(ConfigServerURL) // Use proxy endpoint
			for {
				if ts, err := sc.GetSysvarClockTime(context.Background()); err == nil {
					GlobalClockOffset = ts - time.Now().Unix()
				}
				time.Sleep(30 * time.Second)
			}
		}()
	}
}

// Client is a client for the Zarkham Protocol.
type Client struct {
	RpcClient *rpc.Client
	Signer    solana.PrivateKey
}

// NewClient creates a new Client for the Zarkham Protocol.
func NewClient(rpcEndpoint string, signer solana.PrivateKey) (*Client, error) {
	InitGlobalAuth()
	
	opts := &jsonrpc.RPCClientOpts{
		HTTPClient: &http.Client{
			Transport: &SignedTransport{
				Transport: http.DefaultTransport,
				PrivKey:   globalSessionWallet.PrivateKey,
			},
			Timeout: 30 * time.Second,
		},
	}

	rpcClient := rpc.NewWithCustomRPCClient(jsonrpc.NewClientWithOpts(rpcEndpoint, opts))

	return &Client{
		RpcClient: rpcClient,
		Signer:    signer,
	}, nil
}

// NewReadOnlyClient creates a new client for read-only operations.
func NewReadOnlyClient(rpcEndpoint string) (*Client, error) {
	InitGlobalAuth()
	dummyWallet := solana.NewWallet()

	opts := &jsonrpc.RPCClientOpts{
		HTTPClient: &http.Client{
			Transport: &SignedTransport{
				Transport: http.DefaultTransport,
				PrivKey:   globalSessionWallet.PrivateKey,
			},
			Timeout: 30 * time.Second,
		},
	}

	rpcClient := rpc.NewWithCustomRPCClient(jsonrpc.NewClientWithOpts(rpcEndpoint, opts))

	return &Client{
		RpcClient: rpcClient,
		Signer:    dummyWallet.PrivateKey,
	}, nil
}


func (c *Client) GetProtocolConfigPDA() (solana.PublicKey, uint8, error) {
	return solana.FindProgramAddress([][]byte{[]byte("protocol_config")}, ProgramID)
}

func (c *Client) GetWardenPDA() (solana.PublicKey, uint8, error) {
	return solana.FindProgramAddress([][]byte{[]byte("warden"), c.Signer.PublicKey().Bytes()}, ProgramID)
}

func GetWardenPDAForAuthority(wardenAuthority solana.PublicKey) (solana.PublicKey, uint8, error) {
	return solana.FindProgramAddress([][]byte{[]byte("warden"), wardenAuthority.Bytes()}, ProgramID)
}

func GetSeekerPDA(seekerAuthority solana.PublicKey) (solana.PublicKey, uint8, error) {
	return solana.FindProgramAddress([][]byte{[]byte("seeker"), seekerAuthority.Bytes()}, ProgramID)
}

func GetConnectionPDA(seekerPDA, wardenPDA solana.PublicKey) (solana.PublicKey, uint8, error) {
	return solana.FindProgramAddress([][]byte{[]byte("connection"), seekerPDA.Bytes(), wardenPDA.Bytes()}, ProgramID)
}

func (c *Client) GetSolVaultPDA() (solana.PublicKey, uint8, error) {
	return solana.FindProgramAddress([][]byte{[]byte("sol_vault")}, ProgramID)
}

func (c *Client) GetUsdcVaultATA(solVaultPDA solana.PublicKey) (solana.PublicKey, uint8, error) {
	return solana.FindAssociatedTokenAddress(solVaultPDA, DevnetUsdcMint)
}

func (c *Client) GetUsdtVaultATA(solVaultPDA solana.PublicKey) (solana.PublicKey, uint8, error) {
	return solana.FindAssociatedTokenAddress(solVaultPDA, DevnetUsdtMint)
}


func (c *Client) FetchProtocolConfig() (*ProtocolConfig, error) {
	pda, _, err := c.GetProtocolConfigPDA()
	if err != nil {
		return nil, err
	}
	resp, err := c.RpcClient.GetAccountInfoWithOpts(context.Background(), pda, &rpc.GetAccountInfoOpts{Commitment: rpc.CommitmentConfirmed})
	if err != nil {
		return nil, err
	}
	if resp.Value == nil {
		return nil, fmt.Errorf("protocol config not found")
	}
	return ParseAccount_ProtocolConfig(resp.Value.Data.GetBinary())
}

func (c *Client) FetchWardenAccount() (warden *Warden, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic during deserialization: %v", r)
		}
	}()
	pda, _, err := c.GetWardenPDA()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := c.RpcClient.GetAccountInfoWithOpts(ctx, pda, &rpc.GetAccountInfoOpts{Commitment: rpc.CommitmentConfirmed})
	if err != nil {
		return nil, err
	}
	if resp.Value == nil {
		return nil, fmt.Errorf("warden account not found")
	}
	return ParseAccount_Warden(resp.Value.Data.GetBinary())
}


func (c *Client) InitializeWarden(stakeToken StakeToken, stakeAmount uint64, peerId string, regionCode uint8, ipHash [32]uint8) (*solana.Signature, error) {
	// 1. Fetch Oracle Price
	trustedKey := "pWWTGuYgYTHKzfTSa9WIZOJg46D3LQhbsuSVGgfa7+i6LjG7Ac5TLQN7Dp1M/0r2"

	tokenStr := strings.ToLower(stakeToken.String())
	if stakeToken == StakeToken_Sol { tokenStr = "solana" }
	if stakeToken == StakeToken_Usdc { tokenStr = "usd-coin" }
	if stakeToken == StakeToken_Usdt { tokenStr = "tether" }

	params := url.Values{}
	params.Add("token", tokenStr)
	params.Add("trustedClientKey", trustedKey)
	resp, err := http.Get("https://arkham-dvpn.vercel.app/api/price?" + params.Encode())
	if err != nil { return nil, err }
	defer resp.Body.Close()

	var priceResp struct {
		Price string `json:"price"`
		Timestamp string `json:"timestamp"`
		Signature string `json:"signature"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&priceResp); err != nil { return nil, err }

	price, _ := strconv.ParseUint(priceResp.Price, 10, 64)
	ts, _ := strconv.ParseInt(priceResp.Timestamp, 10, 64)
	sig, _ := hex.DecodeString(priceResp.Signature)
	var finalSig [64]byte
	copy(finalSig[:], sig)

	// 2. Build Ed25519 Instruction
	oracleMsgBuffer := new(bytes.Buffer)
	binary.Write(oracleMsgBuffer, binary.LittleEndian, price)
	binary.Write(oracleMsgBuffer, binary.LittleEndian, ts)
	hasher := sha3.NewLegacyKeccak256()
	hasher.Write(oracleMsgBuffer.Bytes())
	msgHash := hasher.Sum(nil)

	config, _ := c.FetchProtocolConfig()
	
	edData := []byte{1, 0}
	edData = binary.LittleEndian.AppendUint16(edData, 16)   // sig offset
	edData = binary.LittleEndian.AppendUint16(edData, 0xFFFF)
	edData = binary.LittleEndian.AppendUint16(edData, 80)   // key offset
	edData = binary.LittleEndian.AppendUint16(edData, 0xFFFF)
	edData = binary.LittleEndian.AppendUint16(edData, 112)  // msg offset
	edData = binary.LittleEndian.AppendUint16(edData, uint16(len(msgHash)))
	edData = binary.LittleEndian.AppendUint16(edData, 0xFFFF)
	edData = append(edData, sig...)
	edData = append(edData, config.OracleAuthority[:]...)
	edData = append(edData, msgHash...)

	edIx := solana.NewInstruction(Ed25519ProgramID, nil, edData)

	// 3. Build InitializeWarden
	wardenPDA, _, _ := c.GetWardenPDA()
	configPDA, _, _ := c.GetProtocolConfigPDA()
	vaultPDA, _, _ := c.GetSolVaultPDA()
	usdcVault, _, _ := c.GetUsdcVaultATA(vaultPDA)
	usdtVault, _, _ := c.GetUsdtVaultATA(vaultPDA)

	var stakeFrom solana.PublicKey
	if stakeToken == StakeToken_Sol {
		stakeFrom = c.Signer.PublicKey()
	} else {
		mint := DevnetUsdcMint
		if stakeToken == StakeToken_Usdt { mint = DevnetUsdtMint }
		stakeFrom, _, _ = solana.FindAssociatedTokenAddress(c.Signer.PublicKey(), mint)
	}

	initIx, err := NewInitializeWardenInstruction(
		stakeToken, stakeAmount, peerId, regionCode, ipHash, price, ts, finalSig,
		wardenPDA, c.Signer.PublicKey(), configPDA, solana.SysVarInstructionsPubkey,
		stakeFrom, vaultPDA, usdcVault, usdtVault, DevnetUsdcMint, DevnetUsdtMint,
		solana.SystemProgramID, solana.TokenProgramID, AssociatedTokenProgramID,
	)
	if err != nil { return nil, err }

	return c.sendTx([]solana.Instruction{edIx, initIx})
}

func (c *Client) StartConnection(wardenAuthority solana.PublicKey, estimatedMb uint64) (*solana.Signature, error) {
	seekerPDA, _, _ := GetSeekerPDA(c.Signer.PublicKey())
	wardenPDA, _, _ := GetWardenPDAForAuthority(wardenAuthority)
	connPDA, _, _ := GetConnectionPDA(seekerPDA, wardenPDA)
	configPDA, _, _ := c.GetProtocolConfigPDA()

	ix, err := NewStartConnectionInstruction(
		estimatedMb, connPDA, seekerPDA, wardenPDA, c.Signer.PublicKey(), configPDA, solana.SystemProgramID,
	)
	if err != nil { return nil, err }

	return c.sendTx([]solana.Instruction{ix})
}

func (c *Client) DepositEscrow(amount uint64) (*solana.Signature, error) {
	seekerPDA, _, _ := GetSeekerPDA(c.Signer.PublicKey())

	ix, err := NewDepositEscrowInstruction(
		amount,
		false, // usePrivate
		seekerPDA,
		c.Signer.PublicKey(),
		solana.SystemProgramID,
	)
	if err != nil {
		return nil, err
	}

	return c.sendTx([]solana.Instruction{ix})
}

// EndConnection sends a transaction to close an active connection.
func (c *Client) EndConnection(wardenPDA solana.PublicKey) (*solana.Signature, error) {
	seekerAuthority := c.Signer.PublicKey()

	// Derive all PDAs
	seekerPDA, _, err := GetSeekerPDA(seekerAuthority)
	if err != nil {
		return nil, fmt.Errorf("failed to get seeker PDA: %w", err)
	}
	
	// We assume wardenPDA is already the PDA
	connectionPDA, _, err := GetConnectionPDA(seekerPDA, wardenPDA)
	if err != nil {
		return nil, fmt.Errorf("failed to get connection PDA: %w", err)
	}

	// Build instruction
	instruction, err := NewEndConnectionInstruction(
		connectionPDA,
		seekerPDA,
		wardenPDA,
		seekerAuthority,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create EndConnection instruction: %w", err)
	}

	// Get latest blockhash with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	latestBlockhash, err := c.RpcClient.GetLatestBlockhash(ctx, rpc.CommitmentFinalized)
	if err != nil {
		return nil, fmt.Errorf("failed to get latest blockhash: %w", err)
	}

	// Create and sign transaction
	tx, err := solana.NewTransaction(
		[]solana.Instruction{instruction},
		latestBlockhash.Value.Blockhash,
		solana.TransactionPayer(c.Signer.PublicKey()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create transaction: %w", err)
	}

	_, err = tx.Sign(
		func(key solana.PublicKey) *solana.PrivateKey {
			if c.Signer.PublicKey().Equals(key) {
				return &c.Signer
			}
			return nil
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to sign transaction: %w", err)
	}

	// Send transaction with timeout
	sig, err := c.RpcClient.SendTransaction(ctx, tx)
	if err != nil {
		return nil, fmt.Errorf("failed to send transaction: %w", err)
	}

	return &sig, nil
}

func (c *Client) TransferSOL(recipient solana.PublicKey, lamports uint64) (*solana.Signature, error) {
	ix := system.NewTransferInstruction(
		lamports,
		c.Signer.PublicKey(),
		recipient,
	).Build()

	return c.sendTx([]solana.Instruction{ix})
}


func (c *Client) sendTx(instructions []solana.Instruction) (*solana.Signature, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	latest, err := c.RpcClient.GetLatestBlockhash(ctx, rpc.CommitmentFinalized)
	if err != nil { return nil, err }

	// 1. Simulation Phase
	// We build a temp tx just to measure CU
	simTx, err := solana.NewTransaction(instructions, latest.Value.Blockhash, solana.TransactionPayer(c.Signer.PublicKey()))
	if err == nil {
		// Mock sign for simulation (doesn't need to be valid signature, just present)
		// But for accuracy we sign properly
		simTx.Sign(func(key solana.PublicKey) *solana.PrivateKey {
			if c.Signer.PublicKey().Equals(key) { return &c.Signer }
			return nil
		})
		
		simRes, err := c.RpcClient.SimulateTransaction(ctx, simTx)
		if err == nil && simRes.Value.Err == nil && simRes.Value.UnitsConsumed != nil {
			// 2. Optimization Phase
			// Add buffer
			cuLimit := uint32(*simRes.Value.UnitsConsumed + 5000)
			
			// Prepend CU instructions
			cuLimitIx := NewSetComputeUnitLimitInstruction(cuLimit)
			cuPriceIx := NewSetComputeUnitPriceInstruction(1000) // 1000 micro-lamports priority
			
			instructions = append([]solana.Instruction{cuLimitIx, cuPriceIx}, instructions...)
		}
	}

	// 3. Execution Phase
	tx, err := solana.NewTransaction(instructions, latest.Value.Blockhash, solana.TransactionPayer(c.Signer.PublicKey()))
	if err != nil { return nil, err }

	_, err = tx.Sign(func(key solana.PublicKey) *solana.PrivateKey {
		if c.Signer.PublicKey().Equals(key) { return &c.Signer }
		return nil
	})
	if err != nil { return nil, err }

	sig, err := c.RpcClient.SendTransaction(ctx, tx)
	if err != nil { return nil, err }

	return &sig, nil
}

func (c *Client) GetSysvarClockTime(ctx context.Context) (int64, error) {
	// Clock Sysvar Pubkey
	clockPubkey := solana.MustPublicKeyFromBase58("SysvarC1ock11111111111111111111111111111111")
	
	resp, err := c.RpcClient.GetAccountInfo(ctx, clockPubkey)
	if err != nil { return 0, err }
	if resp.Value == nil { return 0, fmt.Errorf("clock sysvar not found") }

	data := resp.Value.Data.GetBinary()
	if len(data) < 16 { return 0, fmt.Errorf("clock data too short") }

	// Layout: [Slot (8) | TS (8) | Epoch (8) | ...]
	// We skip the slot (8 bytes) and read the unix_timestamp (8 bytes)
	ts := int64(binary.LittleEndian.Uint64(data[8:16]))
	return ts, nil
}

func (c *Client) GetClusterTime(ctx context.Context) (int64, error) {
	// 1. Get current slot from 'confirmed' state
	slot, err := c.RpcClient.GetSlot(ctx, rpc.CommitmentConfirmed)
	if err != nil { return 0, err }
	
	// 2. Try to get block time for this exact slot
	ts, err := c.RpcClient.GetBlockTime(ctx, slot)
	if err == nil && ts != nil {
		return int64(*ts), nil
	}

	// 3. Fallback: Search backwards for the most recent valid block time (up to 50 slots)
	for i := uint64(1); i < 50; i++ {
		ts, err := c.RpcClient.GetBlockTime(ctx, slot-i)
		if err == nil && ts != nil {
			return int64(*ts), nil
		}
	}
	
	return 0, fmt.Errorf("could not find a recent block with time")
}

func (c *Client) GetBalance(pk solana.PublicKey) (uint64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	balance, err := c.RpcClient.GetBalance(ctx, pk, rpc.CommitmentFinalized)
	if err != nil {
		return 0, err
	}
	return balance.Value, nil
}

// SubmitBandwidthProof sends a transaction to the blockchain to submit a bandwidth proof.
func (c *Client) SubmitBandwidthProof(
	mbConsumed uint64,
	seekerPublicKey solana.PublicKey,
	seekerSignature [64]byte,
	timestamp int64,
) (*solana.Signature, error) {
	wardenPublicKey := c.Signer.PublicKey()
	wardenPDA, _, _ := c.GetWardenPDA()
	seekerPDA, _, _ := GetSeekerPDA(seekerPublicKey)
	connectionPDA, _, _ := GetConnectionPDA(seekerPDA, wardenPDA)
	protocolConfigPDA, _, _ := c.GetProtocolConfigPDA()

	// Reconstruct the message hash (MUST match seeker's exactly)
	msgBuffer := new(bytes.Buffer)
	msgBuffer.Write(connectionPDA.Bytes())
	binary.Write(msgBuffer, binary.LittleEndian, mbConsumed)
	binary.Write(msgBuffer, binary.LittleEndian, timestamp)

	hasher := sha3.NewLegacyKeccak256()
	hasher.Write(msgBuffer.Bytes())
	messageHash := hasher.Sum(nil)

	// Warden signs the same message hash
	wardenSignature, err := c.Signer.Sign(messageHash)
	if err != nil {
		return nil, fmt.Errorf("warden failed to sign proof: %w", err)
	}

	// Build Ed25519 instructions
	sigOffset := uint16(16)
	pkOffset := sigOffset + 64
	msgOffset := pkOffset + 32

	// Seeker Sig Instruction
	seekerSigIxData := new(bytes.Buffer)
	seekerSigIxData.WriteByte(1)
	seekerSigIxData.WriteByte(0)
	binary.Write(seekerSigIxData, binary.LittleEndian, sigOffset)
	binary.Write(seekerSigIxData, binary.LittleEndian, uint16(0xFFFF))
	binary.Write(seekerSigIxData, binary.LittleEndian, pkOffset)
	binary.Write(seekerSigIxData, binary.LittleEndian, uint16(0xFFFF))
	binary.Write(seekerSigIxData, binary.LittleEndian, msgOffset)
	binary.Write(seekerSigIxData, binary.LittleEndian, uint16(len(messageHash)))
	binary.Write(seekerSigIxData, binary.LittleEndian, uint16(0xFFFF))
	seekerSigIxData.Write(seekerSignature[:])
	seekerSigIxData.Write(seekerPublicKey[:])
	seekerSigIxData.Write(messageHash)

	seekerSigIx := solana.NewInstruction(Ed25519ProgramID, nil, seekerSigIxData.Bytes())

	// Warden Sig Instruction
	wardenSigIxData := new(bytes.Buffer)
	wardenSigIxData.WriteByte(1)
	wardenSigIxData.WriteByte(0)
	binary.Write(wardenSigIxData, binary.LittleEndian, sigOffset)
	binary.Write(wardenSigIxData, binary.LittleEndian, uint16(0xFFFF))
	binary.Write(wardenSigIxData, binary.LittleEndian, pkOffset)
	binary.Write(wardenSigIxData, binary.LittleEndian, uint16(0xFFFF))
	binary.Write(wardenSigIxData, binary.LittleEndian, msgOffset)
	binary.Write(wardenSigIxData, binary.LittleEndian, uint16(len(messageHash)))
	binary.Write(wardenSigIxData, binary.LittleEndian, uint16(0xFFFF))
	wardenSigIxData.Write(wardenSignature[:])
	wardenSigIxData.Write(wardenPublicKey[:])
	wardenSigIxData.Write(messageHash)

	wardenSigIx := solana.NewInstruction(Ed25519ProgramID, nil, wardenSigIxData.Bytes())

	submitIx, err := NewSubmitBandwidthProofInstruction(
		mbConsumed, timestamp, solana.Signature(seekerSignature), wardenSignature,
		connectionPDA, wardenPDA, seekerPDA, protocolConfigPDA,
		solana.SysVarInstructionsPubkey, c.Signer.PublicKey(),
	)
	if err != nil {
		return nil, err
	}

	return c.sendTx([]solana.Instruction{seekerSigIx, wardenSigIx, submitIx})
}

func (c *Client) GenerateBandwidthProofSignature(wardenAuthority solana.PublicKey, mbConsumed uint64, timestamp int64) (solana.Signature, error) {
	seekerPDA, _, _ := GetSeekerPDA(c.Signer.PublicKey())
	wardenPDA, _, _ := GetWardenPDAForAuthority(wardenAuthority)
	connectionPDA, _, _ := GetConnectionPDA(seekerPDA, wardenPDA)

	msgBuffer := new(bytes.Buffer)
	msgBuffer.Write(connectionPDA.Bytes())
	binary.Write(msgBuffer, binary.LittleEndian, mbConsumed)
	binary.Write(msgBuffer, binary.LittleEndian, timestamp)

	hasher := sha3.NewLegacyKeccak256()
	hasher.Write(msgBuffer.Bytes())
	messageHash := hasher.Sum(nil)

	seekerSignature, err := c.Signer.Sign(messageHash)
	if err != nil {
		return solana.Signature{}, fmt.Errorf("failed to sign message as seeker: %w", err)
	}

	return seekerSignature, nil
}

func (c *Client) CalculateWardenRate(warden *Warden) (uint64, error) {
	config, err := c.FetchProtocolConfig()
	if err != nil {
		return 0, err
	}

	baseRate := config.BaseRatePerMb

	// Geo Premium
	geoPremiumBps := uint16(0)
	for _, gp := range config.GeoPremiums {
		if gp.RegionCode == warden.RegionCode {
			geoPremiumBps = gp.PremiumBps
			break
		}
	}

	// Tier Multiplier
	tierMultiplier := uint16(10000) // Default 1.0x if issue, but struct has 3
	switch warden.Tier {
	case Tier_Bronze:
		tierMultiplier = config.TierMultipliers[0]
	case Tier_Silver:
		tierMultiplier = config.TierMultipliers[1]
	case Tier_Gold:
		tierMultiplier = config.TierMultipliers[2]
	}

	// Calculation logic matches contract
	rateWithGeo := (baseRate * uint64(10000+geoPremiumBps)) / 10000
	rateFinal := (rateWithGeo * uint64(tierMultiplier)) / 10000

	return rateFinal, nil
}

func (c *Client) ClaimEarnings(usePrivate bool) (*solana.Signature, error) {
	wardenPDA, _, _ := c.GetWardenPDA()
	vaultPDA, _, _ := c.GetSolVaultPDA()
	ix, err := NewClaimEarningsInstruction(usePrivate, wardenPDA, c.Signer.PublicKey(), vaultPDA, solana.SystemProgramID)
	if err != nil {
		return nil, err
	}
	return c.sendTx([]solana.Instruction{ix})
}

func (c *Client) FetchSeekerAccount() (*Seeker, error) {
	pda, _, _ := GetSeekerPDA(c.Signer.PublicKey())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := c.RpcClient.GetAccountInfoWithOpts(ctx, pda, &rpc.GetAccountInfoOpts{Commitment: rpc.CommitmentConfirmed})
	if err != nil || resp.Value == nil {
		return &Seeker{Authority: c.Signer.PublicKey()}, nil
	}
	return ParseAccount_Seeker(resp.Value.Data.GetBinary())
}

func (c *Client) IsWardenRegistered() (bool, error) {
	pda, _, err := c.GetWardenPDA()
	if err != nil { return false, err }
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := c.RpcClient.GetAccountInfo(ctx, pda)
	if err != nil {
		if strings.Contains(err.Error(), "not found") { return false, nil }
		return false, err
	}
	return resp.Value != nil, nil
}

func (c *Client) FetchAllWardens() ([]*Warden, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := c.RpcClient.GetProgramAccountsWithOpts(
		ctx,
		ProgramID,
		&rpc.GetProgramAccountsOpts{
			Filters: []rpc.RPCFilter{
				{
					Memcmp: &rpc.RPCFilterMemcmp{
						Offset: 0,
						Bytes:  Account_Warden[:],
					},
				},
			},
		},
	)
	if err != nil { return nil, err }

	var wardens []*Warden
	for _, acc := range resp {
		w, err := manualUnmarshalWarden(acc.Account.Data.GetBinary())
		if err == nil {
			wardens = append(wardens, w)
		}
	}
	return wardens, nil
}

func (c *Client) FetchWardenByPeerID(peerID string) (*Warden, error) {
	wardens, err := c.FetchAllWardens()
	if err != nil {
		return nil, err
	}
	for _, w := range wardens {
		if w.PeerId == peerID {
			return w, nil
		}
	}
	return nil, fmt.Errorf("warden with peer ID %s not found", peerID)
}

func (c *Client) FetchMyConnections(profileType string) ([]*ConnectionResult, error) {
	// 1. Derive the PDA we are filtering for
	var userPDA solana.PublicKey
	if profileType == "seeker" {
		userPDA, _, _ = GetSeekerPDA(c.Signer.PublicKey())
	} else {
		userPDA, _, _ = c.GetWardenPDA()
	}

	// 2. Setup Filters
	// Offset 0: Discriminator (8 bytes)
	// Offset 8: Seeker PDA (32 bytes)
	// Offset 40: Warden PDA (32 bytes)
	memcmpOffset := 8
	if profileType == "warden" {
		memcmpOffset = 40
	}

	// 3. Set a strict timeout for the RPC call
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := c.RpcClient.GetProgramAccountsWithOpts(
		ctx,
		ProgramID,
		&rpc.GetProgramAccountsOpts{
			Filters: []rpc.RPCFilter{
				{
					Memcmp: &rpc.RPCFilterMemcmp{
						Offset: 0,
						Bytes:  Account_Connection[:],
					},
				},
				{
					Memcmp: &rpc.RPCFilterMemcmp{
						Offset: uint64(memcmpOffset),
						Bytes:  userPDA.Bytes(),
					},
				},
			},
		},
	)
	if err != nil {
		return nil, err
	}

	var results []*ConnectionResult
	for _, acc := range resp {
		conn, err := manualUnmarshalConnection(acc.Account.Data.GetBinary())
		if err != nil {
			continue
		}

		results = append(results, &ConnectionResult{
			PublicKey: acc.Pubkey,
			Account:   *conn,
		})
	}
	return results, nil
}

func manualUnmarshalConnection(data []byte) (*Connection, error) {
	if len(data) < 8+32+32+8+8+8+8+8+8+2 { // Minimal size check
		return nil, fmt.Errorf("account data too short")
	}
	offset := 8
	c := &Connection{}
	c.Seeker = solana.PublicKeyFromBytes(data[offset : offset+32])
	offset += 32
	c.Warden = solana.PublicKeyFromBytes(data[offset : offset+32])
	offset += 32
	c.StartedAt = int64(binary.LittleEndian.Uint64(data[offset : offset+8]))
	offset += 8
	c.LastProofAt = int64(binary.LittleEndian.Uint64(data[offset : offset+8]))
	offset += 8
	c.BandwidthConsumed = binary.LittleEndian.Uint64(data[offset : offset+8])
	offset += 8
	
	// Skip BandwidthProofs (Vec) - 4 bytes length + content
	proofsLen := binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4 + (int(proofsLen) * 80) // BandwidthProof is 80 bytes (8+8+64)

	c.AmountEscrowed = binary.LittleEndian.Uint64(data[offset : offset+8])
	offset += 8
	c.AmountPaid = binary.LittleEndian.Uint64(data[offset : offset+8])
	offset += 8
	c.RatePerMb = binary.LittleEndian.Uint64(data[offset : offset+8])
	offset += 8
	c.WardenMultiplier = binary.LittleEndian.Uint16(data[offset : offset+2])
	
	return c, nil
}

func manualUnmarshalWarden(data []byte) (*Warden, error) {
	if len(data) < 8 { return nil, fmt.Errorf("too short") }
	offset := 8
	w := &Warden{}
	w.Authority = solana.PublicKeyFromBytes(data[offset : offset+32])
	offset += 32
	
	l := binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4
	
	if offset+int(l) > len(data) {
		return nil, fmt.Errorf("peer id length %d exceeds data remaining", l)
	}

	w.PeerId = string(data[offset : offset+int(l)])
	offset += int(l)
	
	w.StakeToken = StakeToken(data[offset])
	offset++
	w.StakeAmount = binary.LittleEndian.Uint64(data[offset : offset+8])
	offset += 8
	w.StakeValueUsd = binary.LittleEndian.Uint64(data[offset : offset+8])
	offset += 8
	w.Tier = Tier(data[offset])
	offset++
	w.StakedAt = int64(binary.LittleEndian.Uint64(data[offset : offset+8]))
	offset += 8

	// Skip option check for brevity in porting, or implement full logic
	return w, nil
}

func NewSetComputeUnitLimitInstruction(limit uint32) solana.Instruction {
	data := make([]byte, 5)
	data[0] = 0x02
	binary.LittleEndian.PutUint32(data[1:], limit)
	return solana.NewInstruction(ComputeBudgetProgramID, nil, data)
}

func NewSetComputeUnitPriceInstruction(microLamports uint64) solana.Instruction {
	data := make([]byte, 9)
	data[0] = 0x03
	binary.LittleEndian.PutUint64(data[1:], microLamports)
	return solana.NewInstruction(ComputeBudgetProgramID, nil, data)
}

func (c *Client) WaitForConfirmation(ctx context.Context, sig solana.Signature) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(1 * time.Second):
			out, err := c.RpcClient.GetSignatureStatuses(ctx, true, sig)
			if err != nil {
				continue
			}
			if len(out.Value) > 0 && out.Value[0] != nil {
				if out.Value[0].Err != nil {
					return fmt.Errorf("transaction failed: %v", out.Value[0].Err)
				}
				if out.Value[0].ConfirmationStatus == rpc.ConfirmationStatusConfirmed || out.Value[0].ConfirmationStatus == rpc.ConfirmationStatusFinalized {
					return nil
				}
			}
		}
	}
}

func (c *Client) FetchConnectionAccount(pda solana.PublicKey) (*Connection, error) {
	resp, err := c.RpcClient.GetAccountInfoWithOpts(context.Background(), pda, &rpc.GetAccountInfoOpts{
		Commitment: rpc.CommitmentConfirmed,
	})
	if err != nil {
		return nil, err
	}
	if resp.Value == nil {
		return nil, fmt.Errorf("connection account not found")
	}
	return ParseAccount_Connection(resp.Value.Data.GetBinary())
}
