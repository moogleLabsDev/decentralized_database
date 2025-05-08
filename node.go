package node

import (
	"bytes"
	"context"
	"strconv"
	"strings"
	"sync"

	"ddb/internal/api"
	"ddb/internal/bloomfilter"
	"ddb/internal/broadcast"
	"ddb/internal/cryptod"
	"ddb/internal/database"
	"ddb/internal/utils"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/cloudflare/circl/sign/dilithium/mode5"
	"github.com/ipfs/go-cid"
	libp2p "github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	crypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"golang.org/x/crypto/sha3"
)

var _ api.NodeInterface = (*Node)(nil)
var _ api.BloomFilterInterface = (*bloomfilter.BloomFilter)(nil)
var _ broadcast.NodeInterface = (*Node)(nil)

const keyFilePath = "./node_private_key"

func (n *Node) GetHost() host.Host {
	return n.Host
}

func (n *Node) GetTCPPort() int {
	return n.TCPPort
}

func (n *Node) GetDHT() *dht.IpfsDHT {
	return n.DHT
}

func (n *Node) GetBroadcast() *broadcast.Broadcast {
	return n.Broadcast
}

func (n *Node) GetBloomFilter() api.BloomFilterInterface {
	return n.BloomFilter
}

func (n *Node) SaveBloomState() {
	dbAdapter := &bloomfilter.DatabaseAdapter{DB: n.Database}
	err := n.BloomFilter.SaveToDatabase(dbAdapter, n.Host.ID().String())
	if err != nil {
		log.Printf("Failed to save Bloom filter state: %v", err)
	} else {
		log.Println("Bloom filter state saved successfully.")
	}
}

//const keyFilePath = "./node_private_key"

type Node struct {
	Host        host.Host
	DHT         *dht.IpfsDHT
	Broadcast   *broadcast.Broadcast
	TCPPort     int
	Database    *database.Database
	BloomFilter *bloomfilter.BloomFilter
	PublicKey   mode5.PublicKey
	PrivateKey  mode5.PrivateKey
}

// FileMetadata represents metadata for a file and its associated chunks.
type FileMetadata struct {
	FileHash string           `json:"fileHash"`
	Filename string           `json:"filename"`
	Size     int64            `json:"size"`
	Chunks   []database.Chunk `json:"chunks"`
}

const BloomFilterSize = 9600000
const BloomHashFuncs = 7

func loadOrCreatePrivateKey() (crypto.PrivKey, error) {
	// Check if the private key file exists
	if _, err := os.Stat(keyFilePath); err == nil {
		// Load private key from file
		keyBytes, err := os.ReadFile(keyFilePath)
		if err != nil {
			return nil, fmt.Errorf("failed to read private key file: %v", err)
		}

		// Decode the private key
		key, err := crypto.UnmarshalPrivateKey(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal private key: %v", err)
		}

		return key, nil
	}

	// Generate a new private key if not found
	privKey, _, err := crypto.GenerateKeyPair(crypto.RSA, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	// Save the private key to a file
	keyBytes, err := crypto.MarshalPrivateKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %v", err)
	}

	err = os.WriteFile(keyFilePath, keyBytes, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to write private key to file: %v", err)
	}

	return privKey, nil
}

// Use this function to generate the NodeID using post quantum dilithium mode5

func ConvertDilithiumToLibP2P(dilithiumKey mode5.PrivateKey) (crypto.PrivKey, error) {
	// Hash the Dilithium Private Key using SHA3 to derive a deterministic seed
	hasher := sha3.NewLegacyKeccak256()
	hasher.Write(dilithiumKey.Bytes())
	seed := hasher.Sum(nil)

	// Use the seed to generate an Ed25519 private key for LibP2P
	libp2pPrivKey, _, err := crypto.GenerateEd25519Key(bytes.NewReader(seed))
	if err != nil {
		return nil, fmt.Errorf("failed to convert Dilithium key to LibP2P key: %v", err)
	}

	return libp2pPrivKey, nil
}

func GenerateNodeIDFromPublicKey(publicKey mode5.PublicKey) (peer.ID, error) {
	// Convert the Dilithium public key into a LibP2P public key
	libp2pPubKey, err := ConvertDilithiumPublicKeyToLibP2P(publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to convert public key to LibP2P format: %v", err)
	}

	// Generate a peer ID from the LibP2P public key
	nodeID, err := peer.IDFromPublicKey(libp2pPubKey)
	if err != nil {
		return "", fmt.Errorf("failed to generate Node ID: %v", err)
	}

	return nodeID, nil
}
func ConvertDilithiumPublicKeyToLibP2P(dilithiumPub mode5.PublicKey) (crypto.PubKey, error) {
	// Hash the Dilithium Public Key to derive a deterministic seed
	hasher := sha3.NewLegacyKeccak256()
	hasher.Write(dilithiumPub.Bytes())
	seed := hasher.Sum(nil)

	// Use the seed to generate an Ed25519 public key for LibP2P
	_, libp2pPubKey, err := crypto.GenerateEd25519Key(bytes.NewReader(seed))
	if err != nil {
		return nil, fmt.Errorf("failed to convert Dilithium public key to LibP2P key: %v", err)
	}

	return libp2pPubKey, nil
}

// GenerateBloomFilter creates a Bloom filter for the node's current file metadata.
func (n *Node) GenerateBloomFilter() *bloomfilter.BloomFilter {
	bf := bloomfilter.NewBloomFilter(BloomFilterSize, BloomHashFuncs)
	files, _ := n.Database.GetAllFileHashes()
	for _, fileHash := range files {
		bf.SafeAdd(fileHash)
	}
	return bf
}

// SyncWithPeerBloomFilter syncs the node's state with a peer using Bloom filters.
func (n *Node) SyncWithPeerBloomFilter(peerAddr string) error {
	log.Printf("Syncing with peer at %s using Bloom filter...", peerAddr)

	// Generate local Bloom filter
	localFilter := n.GenerateBloomFilter()

	// Request peer's Bloom filter
	peerFilter, err := n.RequestBloomFilterFromPeer(peerAddr)
	if err != nil {
		return err
	}

	// Compare Bloom filters and find missing files
	missingFiles := n.CompareBloomFilters(localFilter, peerFilter)
	for _, fileHash := range missingFiles {
		log.Printf("Fetching missing file: %s", fileHash)

		// Request missing chunks for the file
		chunks, err := n.Database.GetChunks(fileHash)
		if err != nil {
			log.Printf("Failed to get chunks for file %s: %v", fileHash, err)
			continue
		}

		for _, chunk := range chunks {
			if exists, _ := n.Database.ChunkExists(chunk.ChunkHash); !exists {
				log.Printf("Fetching missing chunk: %s", chunk.ChunkHash)
				chunkData, err := n.RequestChunkFromNode(chunk.ChunkHash, peerAddr)
				if err != nil {
					log.Printf("Failed to fetch chunk %s: %v", chunk.ChunkHash, err)
					continue
				}

				// Save chunk locally
				//chunkPath := fmt.Sprintf("./data/%s/%s", fileHash, chunk.ChunkHash)
				chunkPath := fmt.Sprintf("%s/data/%s/%s", utils.GetRootPath(), fileHash, chunk.ChunkHash)
				if err := os.WriteFile(chunkPath, chunkData, 0644); err != nil {
					log.Printf("Failed to save chunk %s: %v", chunk.ChunkHash, err)
					continue
				}

				// Save chunk metadata
				if err := n.Database.SaveChunk(fileHash, chunk.ChunkHash, int64(len(chunkData)), int(chunk.ChunkIndex)); err != nil {
					log.Printf("Failed to save chunk metadata: %v", err)
				} else {
					log.Printf("Successfully saved chunk %s", chunk.ChunkHash)
				}
			}
		}
	}
	return nil
}

// CompareBloomFilters identifies files that are missing in the peer's filter.
func (n *Node) CompareBloomFilters(local, peer *bloomfilter.BloomFilter) []string {
	localHashes, _ := n.Database.GetAllFileHashes()
	var missingFiles []string
	for _, fileHash := range localHashes {
		if !peer.Test(fileHash) {
			missingFiles = append(missingFiles, fileHash)
		}
	}
	return missingFiles
}

// RequestBloomFilterFromPeer fetches the Bloom filter from a peer.
func (n *Node) RequestBloomFilterFromPeer(peerAddr string) (*bloomfilter.BloomFilter, error) {
	// Implement a protocol to fetch the peer's Bloom filter
	log.Printf("Requesting Bloom filter from peer at %s", peerAddr)
	peerFilter := bloomfilter.NewBloomFilter(BloomFilterSize, BloomHashFuncs)
	return peerFilter, nil
}

func (n *Node) LoadBloomState() {
	dbAdapter := &bloomfilter.DatabaseAdapter{DB: n.Database}
	err := n.BloomFilter.LoadFromDatabase(dbAdapter, n.Host.ID().String())
	if err != nil {
		log.Printf("Failed to load Bloom filter state: %v", err)
	} else {
		log.Println("Bloom filter state loaded successfully.")
	}
}

// NewNode creates a new libp2p host and initializes the DHT and pubsub.
func NewNode(ctx context.Context, port int, tcpPort int, database *database.Database) *Node {

	// Load or create a private key
	//privKey, err := loadOrCreatePrivateKey()
	privateKey, publicKey, err := cryptod.LoadOrCreateDilithiumKeys()
	if err != nil {
		log.Fatalf("Failed to load or create Dilithium keys: %v", err)
	}

	// **Convert Dilithium Private Key to LibP2P Key**
	libp2pPrivKey, err := ConvertDilithiumToLibP2P(privateKey)
	if err != nil {
		log.Fatalf("Failed to convert Dilithium key to LibP2P key: %v", err)
	}

	// **Generate the Node ID**
	//nodeID, err := GenerateNodeIDFromPublicKey(publicKey)
	nodeID, err := peer.IDFromPrivateKey(libp2pPrivKey)
	if err != nil {
		log.Fatalf("Failed to generate Node ID: %v", err)
	}

	// Get the real IP Address of the machine
	localIP, err := GetLocalIPAddress()
	if err != nil {
		log.Printf("Failed to determine local IP address, using 0.0.0.0: %v", err)
		localIP = "0.0.0.0"
	}
	//Create the LibP2P Host using the detected IP
	listenAddr := fmt.Sprintf("/ip4/%s/tcp/%d", localIP, port)
	log.Printf("Node is listening at addr: %s", listenAddr)
	host, err := libp2p.New(
		libp2p.ListenAddrStrings(fmt.Sprintf("/ip4/%s/tcp/%d", localIP, port)),
		libp2p.Identity(libp2pPrivKey),
	)

	if err != nil {
		log.Fatalf("Failed to create host: %v", err)
	}

	//Print Multi-Address with Real IP
	realMultiAddr := fmt.Sprintf("/ip4/%s/tcp/%d/p2p/%s", localIP, port, host.ID().String())
	log.Printf("Node is running at: %s", realMultiAddr)

	fmt.Println("TCPPort:", tcpPort)
	dhtNode, err := dht.New(ctx, host, dht.Mode(dht.ModeServer))
	if err != nil {
		log.Fatalf("Failed to create DHT: %v", err)
	}

	if err := dhtNode.Bootstrap(ctx); err != nil {
		log.Fatalf("Failed to bootstrap DHT: %v", err)
	}
	// Initialize pubsub for broadcasting
	broadcast := broadcast.NewBroadcast(ctx, host, "file-metadata")
	// Initialize Bloom Filter
	bloomFilter := bloomfilter.NewBloomFilter(BloomFilterSize, BloomHashFuncs)
	node := &Node{
		Host:        host,
		DHT:         dhtNode,
		Broadcast:   broadcast,
		TCPPort:     tcpPort,
		Database:    database,
		BloomFilter: bloomFilter,
		PublicKey:   publicKey,
		PrivateKey:  privateKey,
	}

	node.LoadBloomState()
	// Set up the chunk request handler
	node.SetupChunkRequestHandler()
	// Setup TCP Port request handler (NEW)
	node.SetupTCPPortRequestHandler()
	log.Printf("Node started. ID: %s", nodeID)
	log.Printf("Listening on: %s", host.Addrs())

	return node
}

// GetLocalIPAddress retrieves the local machine's IP address.
func GetLocalIPAddress() (string, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80") // Google's public DNS
	if err != nil {
		return "", err
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String(), nil
}

// StartTCPServer starts a TCP server for transferring chunks.
func (n *Node) StartTCPServer() {
	listener, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", n.TCPPort))
	if err != nil {
		log.Fatalf("Failed to start TCP server: %v", err)
	}
	defer listener.Close()

	log.Printf("TCP server running on port %d", n.TCPPort)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept TCP connection: %v", err)
			continue
		}
		go n.handleTCPConnection(conn)
	}
}
func (n *Node) DiscoverTCPPort(bootstrapAddr string) (int, error) {
	log.Printf("🔍 Discovering TCP Port from bootstrap: %s", bootstrapAddr)

	// Extract IP, Libp2p port, and Peer ID
	bootstrapParts := strings.Split(bootstrapAddr, "/")
	if len(bootstrapParts) < 7 {
		log.Fatalf(" Invalid bootstrap format: %s", bootstrapAddr)
		return 0, fmt.Errorf("❌ Invalid bootstrap format")
	}

	peerIP := bootstrapParts[2]
	libp2pPort := bootstrapParts[4]
	peerIDStr := bootstrapParts[6]

	log.Printf("✅ Extracted Peer IP: %s, Libp2p Port: %s, Peer ID: %s", peerIP, libp2pPort, peerIDStr)

	// Convert Peer ID to Libp2p PeerInfo
	peerID, err := peer.Decode(peerIDStr)
	if err != nil {
		log.Fatalf("❌ Failed to decode peer ID: %v", err)
		return 0, fmt.Errorf("❌ Failed to decode peer ID: %v", err)
	}
	peerInfo := peer.AddrInfo{ID: peerID}

	// Connect to the peer using Libp2p
	log.Printf("🔗 Connecting to Libp2p peer: %s", peerID)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := n.Host.Connect(ctx, peerInfo); err != nil {
		log.Fatalf("❌ Failed to connect to peer %s: %v", peerID, err)
		return 0, fmt.Errorf("❌ Failed to connect to peer: %v", err)
	}

	// Open a stream to request the TCP port
	stream, err := n.Host.NewStream(ctx, peerID, "/request-tcp-port/1.0.0")
	if err != nil {
		log.Fatalf("❌ Failed to create stream to peer %s: %v", peerID, err)
		return 0, fmt.Errorf("❌ Failed to create stream: %v", err)
	}
	defer stream.Close()

	// Send the request
	log.Println("✅ Sending REQUEST_TCP_PORT over Libp2p stream...")
	_, err = stream.Write([]byte("REQUEST_TCP_PORT"))
	if err != nil {
		log.Fatalf("❌ Failed to send TCP Port request: %v", err)
		return 0, fmt.Errorf("❌ Failed to send TCP Port request: %v", err)
	}

	// Read response
	log.Println("⏳ Waiting for TCP Port response...")
	buf := make([]byte, 10)
	bytesRead, err := stream.Read(buf)
	if err != nil {
		log.Fatalf("❌ Failed to read TCP Port response: %v", err)
		return 0, fmt.Errorf("❌ Failed to read TCP Port response: %v", err)
	}

	// Convert received string to integer
	tcpPortStr := strings.TrimSpace(string(buf[:bytesRead]))
	tcpPort, err := strconv.Atoi(tcpPortStr)
	if err != nil {
		log.Fatalf("❌ Invalid TCP Port received: %q", tcpPortStr)
		return 0, fmt.Errorf("❌ Invalid TCP Port received: %q", tcpPortStr)
	}

	log.Printf("✅ Discovered TCP Port: %d", tcpPort)
	return tcpPort, nil
}

func (n *Node) SetupTCPPortRequestHandler() {
	n.Host.SetStreamHandler("/request-tcp-port/1.0.0", func(stream network.Stream) {
		defer stream.Close()

		log.Printf("📡 Received TCP port request from peer: %s", stream.Conn().RemotePeer())

		// Respond with the actual TCP port (e.g., 9001)
		tcpPortStr := fmt.Sprintf("%d", n.TCPPort)
		_, err := stream.Write([]byte(tcpPortStr))
		if err != nil {
			log.Printf("❌ Failed to send TCP port response: %v", err)
		} else {
			log.Printf("✅ Sent TCP Port: %s", tcpPortStr)
		}
	})
}

func (n *Node) handleTCPConnection(conn net.Conn) {
	fmt.Println("Connection received incomming requests.")
	defer conn.Close()

	// Read the request type
	buf := make([]byte, 512)
	bytesRead, err := conn.Read(buf)
	if err != nil {
		log.Printf("Failed to read TCP request: %v", err)
		return
	}
	request := string(buf[:bytesRead])
	log.Printf("Received TCP request: %q from %s \n", request, conn.RemoteAddr())
	if request == "SYNC_REQUEST" {
		// Send metadata for all files and chunks
		metadata := n.GetMetadataForSync()
		metadataBytes, err := json.Marshal(metadata)
		if err != nil {
			log.Printf("Failed to serialize metadata: %v", err)
			return
		}
		log.Printf("Sending Metadata JSON: %s", string(metadataBytes))

		_, err = conn.Write(metadataBytes)
		if err != nil {
			log.Printf("Failed to send metadata: %v", err)
		}
	} else if request == "REQUEST_TCP_PORT" {
		log.Printf("Sending TCP Port: %d", n.TCPPort)
		response := fmt.Sprintf("%d", n.TCPPort)
		_, err = conn.Write([]byte(response))
		if err != nil {
			log.Printf("Failed to send TCP port: %v", err)
		}
	} else {
		// Assume the request is a chunk hash
		chunkHash := request
		log.Printf("Received request for chunk: %s", chunkHash)

		// Locate the chunk
		path := fmt.Sprintf("%s/data/", utils.GetRootPath())
		chunkPath := locateChunkFile(path, chunkHash)
		if chunkPath == "" {
			log.Printf("Chunk %s not found", chunkHash)
			conn.Write([]byte("ERROR: Chunk not found"))
			return
		}

		// Read and send the chunk
		data, err := os.ReadFile(chunkPath)
		if err != nil {
			log.Printf("Failed to read chunk %s: %v", chunkHash, err)
			conn.Write([]byte("ERROR: Failed to read chunk"))
			return
		}
		_, err = conn.Write(data)
		if err != nil {
			log.Printf("Failed to send chunk data for %s: %v", chunkHash, err)
		}
	}
}

func (n *Node) SaveBloomStateBlocking() error {
	log.Println("Saving Bloom filter state...")

	err := n.BloomFilter.SaveToDatabase(n.Database, n.Host.ID().String())
	if err != nil {
		log.Printf("Error saving Bloom filter state: %v", err)
		return err
	}

	log.Println("Bloom filter state saved successfully.")
	return nil
}
func (n *Node) GetMetadataForSync() []FileMetadata {
	if n.Database == nil {
		log.Println("Database is not initialized.")
		return []FileMetadata{} // ✅ Return empty array instead of nil
	}

	metadata := n.GetAllFilesMetadata()
	if metadata == nil {
		log.Println("No files found in database.")
		return []FileMetadata{} // ✅ Ensure it's always an empty array, not nil
	}

	return metadata
}

func (n *Node) GetAllFilesMetadata() []FileMetadata {
	rawFiles := n.Database.GetAllFilesWithChunks()
	fmt.Printf("GetAllFilesMetaData from database:")
	var metadata []FileMetadata

	for _, rawFile := range rawFiles {
		metadata = append(metadata, FileMetadata{
			FileHash: rawFile.FileHash,
			Filename: rawFile.Filename,
			Size:     rawFile.Size,
			Chunks:   rawFile.Chunks,
		})
	}
	return metadata
}
func locateChunkFile(dataDir, chunkHash string) string {
	var chunkPath string
	_ = filepath.Walk(dataDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() && filepath.Base(path) == chunkHash {
			chunkPath = path
			return filepath.SkipDir
		}
		return nil
	})
	return chunkPath
}

// PeriodicDHTLogging logs the state of the DHT routing table periodically.
func (n *Node) PeriodicDHTLogging(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			log.Println("Periodic DHT Table Logging:")
			peers := n.DHT.RoutingTable().ListPeers()
			log.Printf("DHT Table for Node %s: %d peers", n.Host.ID(), len(peers))
			for _, p := range peers {
				log.Printf("- Peer: %s", p)
			}
		case <-ctx.Done():
			return
		}
	}
}

// ConnectToPeer connects the current node to a specified peer address.
func (n *Node) ConnectToPeer(ctx context.Context, bootstrapAddr string) {
	// ✅ Extract Peer ID from Bootstrap Multiaddress
	parts := strings.Split(bootstrapAddr, "/")
	if len(parts) < 7 {
		log.Fatalf("❌ Invalid bootstrap address format: %s", bootstrapAddr)
	}
	expectedPeerID := parts[6] // Extract the expected Peer ID

	// ✅ Get Peer Info
	peerInfo, err := peer.AddrInfoFromString(bootstrapAddr)
	if err != nil {
		log.Fatalf("❌ Invalid bootstrap address: %v", err)
	}

	// ✅ Validate that the bootstrap node’s actual ID matches
	if expectedPeerID != peerInfo.ID.String() {
		log.Fatalf("❌ Peer ID mismatch! Expected: %s, but got: %s", expectedPeerID, peerInfo.ID.String())
	}

	// ✅ Connect to the Peer
	err = n.Host.Connect(ctx, *peerInfo)
	if err != nil {
		log.Printf("❌ Failed to connect to bootstrap peer: %v", err)
	} else {
		log.Printf("✅ Connected to bootstrap peer: %s", peerInfo.ID)
	}
}

// BroadcastFileMetadata propagates file metadata to all peers via pubsub.
func (n *Node) BroadcastFileMetadata(hash, filename string, size int64) {
	peers := n.DHT.RoutingTable().ListPeers()
	if len(peers) == 0 {
		log.Println("No peers to broadcast to.")
		return
	}
	if n.BloomFilter.Test(hash) {
		log.Printf("File %s already known in the network, skipping broadcast.", hash)
		return
	}

	n.BloomFilter.SafeAdd(hash)

	message := map[string]interface{}{
		"hash":     hash,
		"filename": filename,
		"size":     size,
		"tcp_port": n.TCPPort,
	}
	msgData, err := json.Marshal(message)
	if err != nil {
		log.Printf("Failed to marshal file metadata: %v", err)
		return
	}

	ctx := context.Background()
	for _, peerID := range peers {
		log.Printf("Connecting to peer: %s", peerID)
		peerInfo := peer.AddrInfo{ID: peerID}
		if err := n.Host.Connect(ctx, peerInfo); err != nil {
			log.Printf("Failed to connect to peer %s: %v", peerID, err)
			continue
		}
		log.Printf("Connected to peer: %s", peerID)
	}

	n.Broadcast.BroadcastMessage(ctx, string(msgData))
	log.Printf("Broadcasted file metadata: %s to %d peers", string(msgData), len(peers))
}

func (n *Node) ListenForBroadcasts(ctx context.Context, api *api.API) {
	subscription, err := n.Broadcast.Topic.Subscribe()
	if err != nil {
		log.Fatalf("Failed to subscribe to topic: %v", err)
	}

	log.Println("Listening for file metadata broadcasts...")
	for {
		msg, err := subscription.Next(ctx)
		if err != nil {
			log.Fatalf("Failed to read broadcast message: %v", err)
		}

		var metadata map[string]interface{}
		if err := json.Unmarshal(msg.Data, &metadata); err != nil {
			log.Printf("Failed to unmarshal broadcast message: %v", err)
			continue
		}

		log.Printf("Received broadcast: %+v", metadata)
		go func() {
			chunkHash := metadata["hash"].(string)
			fileHash := metadata["fileHash"].(string)
			filename := metadata["filename"].(string)
			size := int64(metadata["size"].(float64))
			chunkIndex := metadata["chunkIndex"].(int)
			fmt.Printf("filename===============================>: %+v \n", filename)
			fmt.Printf("chunkIndex=============================>: %+v \n", chunkIndex)
			// Check if the chunk already exists
			exists, err := n.Database.ChunkExists(chunkHash)
			if err != nil {
				log.Printf("Failed to check if chunk %s exists: %v", chunkHash, err)
				return
			}
			if exists {
				log.Printf("Chunk %s already exists. Skipping download.", chunkHash)
				return
			}

			log.Printf("Requesting chunk %s from network...", chunkHash)
			chunkData, err := n.RequestChunkFromPeers(chunkHash, fileHash, chunkIndex, n.Database)
			if err != nil {
				log.Printf("Failed to retrieve chunk %s: %v", chunkHash, err)
				return
			}

			// Save the chunk locally
			//chunkDir := fmt.Sprintf("./data/%s", fileHash)
			chunkDir := fmt.Sprintf("%s/data/%s", utils.GetRootPath(), fileHash)
			os.MkdirAll(chunkDir, 0755)
			chunkPath := fmt.Sprintf("%s/%s", chunkDir, chunkHash)
			err = os.WriteFile(chunkPath, chunkData, 0644)
			if err != nil {
				log.Printf("Failed to save chunk %s locally: %v", chunkHash, err)
				return
			}

			err = n.Database.SaveChunk(fileHash, chunkHash, size, chunkIndex)
			if err != nil {
				log.Printf("Failed to save chunk metadata: %v", err)
			} else {
				log.Printf("Stored chunk %s locally after broadcast.", chunkHash)
			}
		}()
	}
}

func (n *Node) PeriodicDHTBootstrap(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			log.Println("Refreshing DHT bootstrap...")
			if err := n.DHT.Bootstrap(ctx); err != nil {
				log.Printf("Failed to refresh DHT bootstrap: %v", err)
			}
		case <-ctx.Done():
			return
		}
	}
}

func (n *Node) RequestFileMetadataFromPeer(peerInfo peer.AddrInfo, fileHash string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	stream, err := n.Host.NewStream(ctx, peerInfo.ID, "/file-metadata/1.0.0")
	if err != nil {
		return nil, fmt.Errorf("failed to create stream to peer %s: %v", peerInfo.ID, err)
	}
	defer stream.Close()

	// Send file hash to request metadata
	_, err = stream.Write([]byte(fileHash))
	if err != nil {
		return nil, fmt.Errorf("failed to send file hash: %v", err)
	}

	// Read response (chunk hashes)
	data, err := io.ReadAll(stream)
	if err != nil {
		return nil, fmt.Errorf("failed to read metadata response: %v", err)
	}

	var chunkHashes []string
	if err := json.Unmarshal(data, &chunkHashes); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata response: %v", err)
	}
	return chunkHashes, nil
}

func (n *Node) SetupChunkRequestHandler() {
	n.Host.SetStreamHandler("/chunk-request/1.0.0", func(stream network.Stream) {
		defer stream.Close()

		// Read the chunk hash from the stream
		hashBuf, err := io.ReadAll(stream)
		if err != nil {
			log.Printf("Failed to read chunk hash from stream: %v", err)
			return
		}

		rootPath := utils.GetRootPath()
		dataPath := filepath.Join(rootPath, "data")
		chunkHash := string(hashBuf)
		log.Printf("Received request for chunk: %s", chunkHash)

		// Locate the chunk in the local repository
		var chunkPath string
		err = filepath.Walk(dataPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.IsDir() && info.Name() == chunkHash {
				chunkPath = path
				return filepath.SkipDir
			}
			return nil
		})

		if err != nil || chunkPath == "" {
			log.Printf("Chunk %s not found locally: %v", chunkHash, err)
			return
		}

		// Read the chunk data
		chunkData, err := os.ReadFile(chunkPath)
		if err != nil {
			log.Printf("Failed to read chunk file %s: %v", chunkPath, err)
			return
		}

		// Send the chunk data to the requesting peer
		_, err = stream.Write(chunkData)
		if err != nil {
			log.Printf("Failed to send chunk data: %v", err)
		} else {
			log.Printf("Successfully sent chunk %s to peer", chunkHash)
		}
	})
}

// SyncFromPeer syncs the database and files from a specified peer
func (n *Node) SyncFromPeer(bootstrapAddr string, peerAddr string) error {
	log.Printf("🔄 Starting sync process from peer: %s", bootstrapAddr)
	bootstrapParts := strings.Split(bootstrapAddr, ":")
	bootstrapIP := bootstrapParts[0]

	// Discover TCP Port
	tcpPort, err := n.DiscoverTCPPort(bootstrapAddr)
	if err != nil {
		log.Fatalf("❌ Failed to discover TCP port from peer %s: %v", bootstrapAddr, err)
		return fmt.Errorf("failed to discover TCP port: %v", err)
	}

	bootstrapParts = strings.Split(bootstrapAddr, "/")
	if len(bootstrapParts) < 7 {
		log.Fatalf("❌ Invalid bootstrap format: %s", bootstrapAddr)
	}
	bootstrapIP = bootstrapParts[2]
	peerTCPAddr := fmt.Sprintf("%s:%d", bootstrapIP, tcpPort)
	log.Printf("✅ Connecting to peer at TCP address: %s", peerTCPAddr)

	// Establish a connection with the peer
	conn, err := net.Dial("tcp", peerTCPAddr)
	if err != nil {
		log.Fatalf("❌ Failed to connect to peer with multiaddress %s: %v", bootstrapAddr, err)
		return fmt.Errorf("failed to connect to peer with multiaddress %s: %v", bootstrapAddr, err)
	}
	defer conn.Close()
	log.Printf("✅ Successfully connected to peer on TCP Port: %d", tcpPort)

	// Send a sync request to the peer
	_, err = conn.Write([]byte("SYNC_REQUEST"))
	if err != nil {
		log.Fatalf("❌ Failed to send sync request: %v", err)
		return fmt.Errorf("failed to send sync request: %v", err)
	}

	// Receive metadata (list of files and chunks) from the peer
	metadata, err := io.ReadAll(conn)
	if err != nil {
		log.Fatalf("❌ Failed to read metadata: %v", err)
		return fmt.Errorf("failed to read metadata: %v", err)
	}

	// Debugging metadata response
	log.Printf("📦 Raw Metadata Received (first 400 bytes): %q", metadata[:400])

	// Validate JSON metadata
	if len(metadata) == 0 || (metadata[0] != '{' && metadata[0] != '[') {
		log.Fatalf("❌ Received non-JSON metadata, possible corruption: %q", metadata[:100])
		return fmt.Errorf("corrupt metadata received")
	}

	// Parse metadata into a structured format
	var files []FileMetadata
	err = json.Unmarshal(metadata, &files)
	if err != nil {
		log.Fatalf("❌ Failed to parse metadata: %v", err)
		log.Printf("📦 Raw metadata that failed to parse: %q", metadata[:200])
		return fmt.Errorf("failed to parse metadata: %v", err)
	}

	// **🔴 Blocking Sync Process Using WaitGroup**
	var wg sync.WaitGroup
	syncComplete := make(chan bool)

	// Process each file and its chunks
	for _, file := range files {
		log.Printf("📂 Syncing file: %s (FileHash: %s)", file.Filename, file.FileHash)

		// Ensure the file directory exists
		//fileDir := fmt.Sprintf("./data/%s", file.FileHash)
		fileDir := fmt.Sprintf("%s/data/%s", utils.GetRootPath(), file.FileHash)
		if err := os.MkdirAll(fileDir, 0755); err != nil {
			log.Printf("❌ Failed to create directory %s: %v", fileDir, err)
			continue
		}

		// Check if the file already exists
		if !n.Database.FileExists(file.FileHash) {
			if err := n.Database.SaveFile(file.Filename, file.FileHash, file.Size, fileDir); err != nil {
				log.Printf("❌ Failed to save file metadata: %v", err)
			}
			//Store the embedding for file hash
			if err := n.Database.SaveFileEmbedding(file.FileHash); err != nil {
				log.Printf("❌ Failed to save file embedding: %v", err)
			}

		}

		// Add file hash to Bloom filter
		n.BloomFilter.SafeAdd(file.FileHash)

		// Fetch missing chunks in parallel
		for _, chunk := range file.Chunks {
			// If chunk exists, skip it
			if exists, _ := n.Database.ChunkExists(chunk.ChunkHash); exists {
				log.Printf("✔️  Chunk %s already exists. Skipping.", chunk.ChunkHash)
				continue
			}

			// Increment the wait group counter
			wg.Add(1)

			// Fetch chunk in a separate goroutine
			go func(chunk database.Chunk, fileHash string) {
				defer wg.Done()

				log.Printf("📡 Fetching missing chunk %s for file %s", chunk.ChunkHash, fileHash)
				err := n.FetchChunk(chunk, peerTCPAddr, fileHash)
				if err != nil {
					log.Printf("❌ Failed to fetch chunk %s: %v", chunk.ChunkHash, err)
					return
				}

				// Save chunk metadata
				if err := n.Database.SaveChunk(fileHash, chunk.ChunkHash, chunk.Size, chunk.ChunkIndex); err != nil {
					log.Printf("❌ Failed to save chunk metadata for %s: %v", chunk.ChunkHash, err)
					return
				}

				// Add chunk hash to Bloom filter
				n.BloomFilter.SafeAdd(chunk.ChunkHash)
			}(chunk, file.FileHash)
		}
	}

	// **Block execution until all goroutines complete**
	go func() {
		wg.Wait()
		syncComplete <- true
	}()

	// **Blocking call: Wait until sync is complete**
	<-syncComplete

	// Save Bloom filter state after sync
	if err := n.BloomFilter.SaveToDatabase(n.Database, n.Host.ID().String()); err != nil {
		log.Printf("❌ Failed to save updated Bloom filter state: %v", err)
	} else {
		log.Println("✅ Bloom filter state saved successfully after sync.")
	}

	log.Println("✅ Sync process completed successfully.")
	return nil
}

// FetchChunk fetches a single chunk via TCP and saves it locally and in the database
func (n *Node) FetchChunk(chunk database.Chunk, peerAddr, fileHash string) error {
	log.Printf("📡 Attempting to fetch chunk %s from %s...", chunk.ChunkHash, peerAddr)
	peerTCPAddr := peerAddr
	// Establish a connection with the peer
	conn, err := net.Dial("tcp", peerTCPAddr)
	if err != nil {
		log.Fatalf("Failed to connect to peer %s: %v", peerTCPAddr, err)
		return fmt.Errorf("failed to connect to peer: %v", err)
	}
	defer conn.Close()

	// Send chunk request
	log.Printf("Requesting chunk %s from %s", chunk.ChunkHash, peerTCPAddr)

	// Send the chunk hash to request the chunk data
	_, err = conn.Write([]byte(chunk.ChunkHash))
	if err != nil {
		return fmt.Errorf("failed to send chunk request: %v", err)
	}

	// Read the chunk data from the connection
	data, err := io.ReadAll(conn)
	if err != nil {
		return fmt.Errorf("failed to read chunk data: %v", err)
	}

	// DEBUG: Log chunk size
	log.Printf("Received chunk %s (Size: %d bytes)", chunk.ChunkHash, len(data))

	// Ensure the directory for the file exists
	//chunkDir := fmt.Sprintf("./data/%s", fileHash)
	chunkDir := fmt.Sprintf("%s/data/%s", utils.GetRootPath(), fileHash)
	if err := os.MkdirAll(chunkDir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %v", chunkDir, err)
	}

	// Save the chunk data locally
	chunkPath := fmt.Sprintf("%s/%s", chunkDir, chunk.ChunkHash)
	if err := os.WriteFile(chunkPath, data, 0644); err != nil {
		log.Fatalf("Failed to save chunk: %v", err)
		return fmt.Errorf("failed to save chunk: %v", err)
	}

	// Save the chunk metadata in the database
	if err := n.Database.SaveChunk(fileHash, chunk.ChunkHash, chunk.Size, int(chunk.ChunkIndex)); err != nil {
		log.Printf("Failed to save chunk metadata for %s: %v", chunk.ChunkHash, err)
		return fmt.Errorf("failed to save chunk metadata: %v", err)
	}

	log.Printf("Fetched and saved chunk %s for file %s", chunk.ChunkHash, fileHash)
	return nil
}

func (n Node) RequestChunkFromPeers(chunkHash, fileHash string, chunkIndex int, database *database.Database) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	peerInfoChan := n.DHT.FindProvidersAsync(ctx, cid.NewCidV1(cid.Raw, []byte(chunkHash)), 1)

	for peerInfo := range peerInfoChan {
		log.Printf("Attempting to fetch chunk %s from peer %s", chunkHash, peerInfo.ID)

		// Connect to the peer
		if err := n.Host.Connect(ctx, peerInfo); err != nil {
			log.Printf("Failed to connect to peer %s: %v", peerInfo.ID, err)
			continue
		}

		// Open a new stream
		stream, err := n.Host.NewStream(ctx, peerInfo.ID, "/chunk-request/1.0.0")
		if err != nil {
			log.Printf("Failed to create stream to peer %s: %v", peerInfo.ID, err)
			continue
		}

		// Ensure stream is closed after use
		defer func() {
			_ = stream.Close() // Ensure no error blocks execution
		}()

		// Send the chunk hash to the peer
		if _, err = stream.Write([]byte(chunkHash)); err != nil {
			log.Printf("Failed to send chunk hash to peer %s: %v", peerInfo.ID, err)
			continue
		}

		// Read the chunk data from the peer
		chunkData, err := io.ReadAll(stream)
		if err != nil {
			log.Printf("Failed to read chunk data from peer %s: %v", peerInfo.ID, err)
			continue
		}

		// Ensure the directory exists
		//chunkDir := fmt.Sprintf("./data/%s", fileHash)
		chunkDir := fmt.Sprintf("%s/data/%s", utils.GetRootPath(), fileHash)
		if err := os.MkdirAll(chunkDir, 0755); err != nil {
			log.Printf("Failed to create directory %s: %v", chunkDir, err)
			return nil, fmt.Errorf("failed to create chunk directory: %w", err)
		}

		// Save the chunk data locally
		chunkPath := fmt.Sprintf("%s/%s", chunkDir, chunkHash)
		if err = os.WriteFile(chunkPath, chunkData, 0644); err != nil {
			log.Printf("Failed to save chunk %s locally: %v", chunkHash, err)
			return nil, fmt.Errorf("failed to save chunk locally: %w", err)
		}

		// Save the chunk metadata in the database
		if err = database.SaveChunk(fileHash, chunkHash, int64(len(chunkData)), int(chunkIndex)); err != nil {
			log.Printf("Failed to save chunk metadata for %s: %v", chunkHash, err)
			return nil, fmt.Errorf("failed to save chunk metadata: %w", err)
		}

		log.Printf("Successfully retrieved and stored chunk %s", chunkHash)
		return chunkData, nil // Success; no need to iterate further
	}

	// If no peer provided the chunk, return an error
	return nil, fmt.Errorf("chunk %s not found in network", chunkHash)
}

func (n *Node) RequestChunkFromPeer(peerInfo peer.AddrInfo, chunkHash string) ([]byte, error) {
	// Implement a protocol to request chunk data from a peer
	log.Printf("Attempting to connect to peer %s for chunk %s", peerInfo.ID, chunkHash)

	stream, err := n.Host.NewStream(context.Background(), peerInfo.ID, "/chunk-request/1.0.0")
	if err != nil {
		return nil, fmt.Errorf("failed to create stream to peer %s: %v", peerInfo.ID, err)
	}
	defer stream.Close()

	// Send the chunk request
	_, err = stream.Write([]byte(chunkHash))
	if err != nil {
		return nil, fmt.Errorf("failed to send chunk request: %v", err)
	}

	// Read the chunk data from the peer
	data, err := io.ReadAll(stream)
	if err != nil {
		return nil, fmt.Errorf("failed to read chunk data: %v", err)
	}

	return data, nil
}

func (n *Node) RequestChunkFromNode(chunkHash string, peerAddr string) ([]byte, error) {
	log.Printf("Connecting to peer %s to fetch chunk %s...", peerAddr, chunkHash)

	// Establish a TCP connection to the peer
	conn, err := net.Dial("tcp", peerAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to peer %s: %v", peerAddr, err)
	}
	defer conn.Close()

	// Send the chunk hash
	_, err = conn.Write([]byte(chunkHash))
	if err != nil {
		return nil, fmt.Errorf("failed to send chunk hash to peer %s: %v", peerAddr, err)
	}

	// Read the chunk data
	chunkData, err := io.ReadAll(conn)
	if err != nil {
		return nil, fmt.Errorf("failed to read chunk data from peer %s: %v", peerAddr, err)
	}

	log.Printf("Successfully fetched chunk %s from peer %s.", chunkHash, peerAddr)
	return chunkData, nil
}

func (n *Node) FetchChunksFromPeers(fileHash string) ([]database.Chunk, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var chunks []database.Chunk
	peerInfoChan := n.DHT.FindProvidersAsync(ctx, cid.NewCidV1(cid.Raw, []byte(fileHash)), 10)
	for peerInfo := range peerInfoChan {
		if err := n.Host.Connect(ctx, peerInfo); err != nil {
			log.Printf("Failed to connect to peer %s: %v", peerInfo.ID, err)
			continue
		}

		// Request chunk metadata from peer
		metadata, err := n.RequestFileMetadataFromPeer(peerInfo, fileHash)
		if err != nil {
			log.Printf("Failed to request metadata from peer %s: %v", peerInfo.ID, err)
			continue
		}

		// Request each chunk
		for _, chunkHash := range metadata {
			chunkData, err := n.RequestChunkFromPeer(peerInfo, chunkHash)
			if err != nil {
				log.Printf("Failed to retrieve chunk %s from peer %s: %v", chunkHash, peerInfo.ID, err)
				continue
			}
			chunks = append(chunks, database.Chunk{ChunkHash: chunkHash, Data: chunkData})
		}
	}

	if len(chunks) == 0 {
		return nil, fmt.Errorf("no chunks found for file %s", fileHash)
	}
	return chunks, nil
}
