package ryne

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"sync"
	"time"

	"zarkham/core/logger"
	"zarkham/core/p2p"
	"zarkham/core/solana"

	"golang.org/x/crypto/sha3"
)

type Service struct {
	mu           sync.Mutex
	p2p          *p2p.Manager
	solana       *solana.Client
	isRunning    bool
	stopChan     chan struct{}
	submitTC     bool
}

func NewService(pm *p2p.Manager, sc *solana.Client, submitTC bool) *Service {
	return &Service{
		p2p:      pm,
		solana:   sc,
		stopChan: make(chan struct{}),
		submitTC: submitTC,
	}
}

func (s *Service) Start() {
	s.mu.Lock()
	if s.isRunning {
		s.mu.Unlock()
		return
	}
	s.isRunning = true
	s.mu.Unlock()

	logger.RYNE("Initialising Bandwidth Aggregation Engine (SubmitTC=%v)...", s.submitTC)
	go s.aggregatorLoop()
}

func (s *Service) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.isRunning {
		return
	}
	close(s.stopChan)
	s.isRunning = false
	logger.RYNE("Engine offline.")
}

func (s *Service) aggregatorLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopChan:
			return
		case <-ticker.C:
			s.processConnections()
		}
	}
}

func (s *Service) processConnections() {
	tunnels := s.p2p.GetActiveTunnels()
	for _, pid := range tunnels {
		conn := s.p2p.GetConnection(pid)
		if conn == nil { continue }

		if !conn.IsWarden {
			s.processSeekerConnection(conn)
		}
	}
}

func (s *Service) processSeekerConnection(conn *p2p.WireGuardConnection) {
	rx, tx := conn.GetStats()
	totalBytes := rx + tx
	totalMB := totalBytes / 1024 / 1024
	
	if totalMB == 0 { return }
	
	if len(conn.CertBuffer) > 0 && totalMB <= conn.CertBuffer[len(conn.CertBuffer)-1].CumulativeMB {
		return
	}

	ts := time.Now().Unix() + solana.GlobalClockOffset - 5
	tc := p2p.ThroughputCertificate{
		SeekerAuthority:   conn.SeekerAuthority,
		WardenAuthority:   conn.WardenAuthority,
		ConnectionPDA:     conn.ConnectionPDA,
		CumulativeMB:      totalMB,
		BytesThisInterval: totalBytes,
		Timestamp:         ts,
		SequenceNumber:    conn.SequenceCount,
	}
	conn.SequenceCount++

	msgBuffer := new(bytes.Buffer)
	msgBuffer.Write(tc.ConnectionPDA.Bytes())
	binary.Write(msgBuffer, binary.LittleEndian, tc.CumulativeMB)
	binary.Write(msgBuffer, binary.LittleEndian, tc.Timestamp)

	hasher := sha3.NewLegacyKeccak256()
	hasher.Write(msgBuffer.Bytes())
	messageHash := hasher.Sum(nil)

	sig, err := s.solana.Signer.Sign(messageHash)
	if err != nil {
		logger.Error("RYNE", "Signature failure: %v", err)
		return
	}
	copy(tc.SeekerSignature[:], sig[:])

	conn.CertBuffer = append(conn.CertBuffer, tc)
	logger.RYNE("Throughput Cert [%d]: %d MB total usage attested.", tc.SequenceNumber, tc.CumulativeMB)

	if len(conn.CertBuffer) >= 12 {
		s.sendBatchToWarden(conn)
	}
}

func (s *Service) sendBatchToWarden(conn *p2p.WireGuardConnection) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	stream, err := s.p2p.Host().NewStream(ctx, conn.WardenPeerID, p2p.ProtocolBandwidth)
	if err != nil {
		return
	}
	defer stream.Close()

	var highestMB uint64
	for _, c := range conn.CertBuffer {
		if c.CumulativeMB > highestMB {
			highestMB = c.CumulativeMB
		}
	}

	batch := p2p.BatchedCertificate{
		Certificates: conn.CertBuffer,
		BatchID:      uint64(time.Now().Unix()),
	}

	logger.RYNE("Uplinking Batch %d (%d TCs, Peak Session: %d MB)...", batch.BatchID, len(batch.Certificates), highestMB)

	if err := json.NewEncoder(stream).Encode(batch); err != nil {
		logger.Error("RYNE", "Uplink failure to %s: %v", conn.WardenPeerID, err)
		return
	}

	var ack p2p.P2PBandwidthAck
	if err := json.NewDecoder(stream).Decode(&ack); err == nil {
		logger.RYNE("Batch accepted by Warden. Last Confirmed On-Chain: Seq %d", ack.LastSubmittedSeq)
		conn.CertBuffer = nil

		if ack.CurrentClusterTime != 0 {
			newOffset := ack.CurrentClusterTime - time.Now().Unix()
			if newOffset != conn.ClockOffset {
				logger.RYNE("Drift Correction: Shifting clock by %ds to match Cluster.", newOffset - conn.ClockOffset)
				conn.ClockOffset = newOffset
			}
		}
	}
}