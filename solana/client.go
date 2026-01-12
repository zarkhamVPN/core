package solana

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/programs/system"
	"github.com/gagliardetto/solana-go/rpc"
	"golang.org/x/crypto/sha3"
)

var AssociatedTokenProgramID = solana.MustPublicKeyFromBase58("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")
var Ed25519ProgramID = solana.MustPublicKeyFromBase58("Ed25519SigVerify111111111111111111111111111")

// Devnet Addresses:
var (
	DevnetUsdcMint = solana.MustPublicKeyFromBase58("4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU")
	DevnetUsdtMint = solana.MustPublicKeyFromBase58("4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU")
)

// Client is a client for the Zarkham Protocol.
type Client struct {
	RpcClient *rpc.Client
	Signer    solana.PrivateKey
}

// NewClient creates a new Client for the Zarkham Protocol.
func NewClient(rpcEndpoint string, signer solana.PrivateKey) (*Client, error) {
	return &Client{
		RpcClient: rpc.New(rpcEndpoint),
		Signer:    signer,
	}, nil
}

// NewReadOnlyClient creates a new client for read-only operations.
func NewReadOnlyClient(rpcEndpoint string) (*Client, error) {
	dummyWallet := solana.NewWallet()
	return &Client{
		RpcClient: rpc.New(rpcEndpoint),
		Signer:    dummyWallet.PrivateKey,
	}, nil
}

// --- PDA Helpers ---

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

// --- Account Fetchers ---

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
	resp, err := c.RpcClient.GetAccountInfoWithOpts(context.Background(), pda, &rpc.GetAccountInfoOpts{Commitment: rpc.CommitmentConfirmed})
	if err != nil {
		return nil, err
	}
	if resp.Value == nil {
		return nil, fmt.Errorf("warden account not found")
	}
	return ParseAccount_Warden(resp.Value.Data.GetBinary())
}

// --- Instructions ---

func (c *Client) InitializeWarden(stakeToken StakeToken, stakeAmount uint64, peerId string, regionCode uint8, ipHash [32]uint8) (*solana.Signature, error) {
	// 1. Fetch Oracle Price
	trustedKey := os.Getenv("TRUSTED_CLIENT_KEY")
	if trustedKey == "" {
		return nil, fmt.Errorf("TRUSTED_CLIENT_KEY not set")
	}

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

func (c *Client) EndConnection(wardenAuthority solana.PublicKey) (*solana.Signature, error) {
	seekerPDA, _, _ := GetSeekerPDA(c.Signer.PublicKey())
	wardenPDA, _, _ := GetWardenPDAForAuthority(wardenAuthority)
	connPDA, _, _ := GetConnectionPDA(seekerPDA, wardenPDA)

	ix, err := NewEndConnectionInstruction(connPDA, seekerPDA, wardenPDA, c.Signer.PublicKey())
	if err != nil { return nil, err }

	return c.sendTx([]solana.Instruction{ix})
}

// --- Utils ---

func (c *Client) sendTx(instructions []solana.Instruction) (*solana.Signature, error) {
	latest, err := c.RpcClient.GetLatestBlockhash(context.Background(), rpc.CommitmentFinalized)
	if err != nil { return nil, err }

	tx, err := solana.NewTransaction(instructions, latest.Value.Blockhash, solana.TransactionPayer(c.Signer.PublicKey()))
	if err != nil { return nil, err }

	_, err = tx.Sign(func(key solana.PublicKey) *solana.PrivateKey {
		if c.Signer.PublicKey().Equals(key) { return &c.Signer }
		return nil
	})
	if err != nil { return nil, err }

	sig, err := c.RpcClient.SendTransaction(context.Background(), tx)
	if err != nil { return nil, err }

	return &sig, nil
}

func (c *Client) GetBalance(pk solana.PublicKey) (uint64, error) {
	balance, err := c.RpcClient.GetBalance(context.Background(), pk, rpc.CommitmentFinalized)
	if err != nil {
		return 0, err
	}
	return balance.Value, nil
}

// SubmitBandwidthProof sends a transaction to the blockchain to submit a bandwidth proof.
func (c *Client) SubmitBandwidthProof(
	mbConsumed uint64,
	seekerPublicKey solana.PublicKey,
	seekerSignature solana.Signature,
	timestamp int64,
) (*solana.Signature, error) {
	wardenPublicKey := c.Signer.PublicKey()
	wardenPDA, _, _ := c.GetWardenPDA()
	seekerPDA, _, _ := GetSeekerPDA(seekerPublicKey)
	connectionPDA, _, _ := GetConnectionPDA(seekerPDA, wardenPDA)
	protocolConfigPDA, _, _ := c.GetProtocolConfigPDA()

	msgBuffer := new(bytes.Buffer)
	msgBuffer.Write(connectionPDA.Bytes())
	binary.Write(msgBuffer, binary.LittleEndian, mbConsumed)
	binary.Write(msgBuffer, binary.LittleEndian, timestamp)

	hasher := sha3.NewLegacyKeccak256()
	hasher.Write(msgBuffer.Bytes())
	messageHash := hasher.Sum(nil)

	wardenSignature, _ := c.Signer.Sign(messageHash)

	// Build Ed25519 instructions
	sigOffset := uint16(16)
	pkOffset := sigOffset + 64
	msgOffset := pkOffset + 32

	// Seeker Sig
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

	// Warden Sig
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
		mbConsumed, timestamp, seekerSignature, wardenSignature,
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

	return c.Signer.Sign(messageHash)
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
	resp, err := c.RpcClient.GetAccountInfoWithOpts(context.Background(), pda, &rpc.GetAccountInfoOpts{Commitment: rpc.CommitmentConfirmed})
	if err != nil || resp.Value == nil {
		return &Seeker{Authority: c.Signer.PublicKey()}, nil
	}
	return ParseAccount_Seeker(resp.Value.Data.GetBinary())
}
