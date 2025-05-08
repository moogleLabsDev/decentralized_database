package api

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"ddb/internal/broadcast"
	"ddb/internal/database"

	"github.com/ipfs/go-cid"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/host"
	// "github.com/libp2p/go-libp2p/core/peer"
)

// NodeInterface defines the methods that the API needs from Node.
type NodeInterface interface {
	RequestChunkFromPeers(chunkHash, fileHash string, chunkIndex int, db *database.Database) ([]byte, error)
	BroadcastFileMetadata(hash, filename string, size int64)
	GetHost() host.Host
	GetTCPPort() int
	GetDHT() *dht.IpfsDHT
	GetBroadcast() *broadcast.Broadcast
	GetBloomFilter() BloomFilterInterface
}

// BloomFilterInterface defines methods for the Bloom filter
type BloomFilterInterface interface {
	SafeTest(data string) bool
	SafeAdd(data string)
	SaveToDatabase(db database.BloomDatabase, nodeID string) error
}

type API struct {
	Node     NodeInterface
	Database *database.Database
}

// NewAPI initializes the API.
func NewAPI(node NodeInterface, database *database.Database) *API {
	return &API{Node: node, Database: database}
}
func (api *API) UploadFileHandler(w http.ResponseWriter, r *http.Request) {
	// Read the uploaded file
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Failed to read file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Read the file content into memory
	content, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, "Failed to read file content", http.StatusInternalServerError)
		return
	}

	// Compute file hash
	fileHash := fmt.Sprintf("%x", sha256.Sum256(content))
	chunkSize := 5 * 1024 * 1024 // 5 MB
	totalChunks := len(content) / chunkSize
	if len(content)%chunkSize != 0 {
		totalChunks++
	}

	// Save file metadata to the database
	filePath := fmt.Sprintf("./data/%s", fileHash)
	err = api.Database.SaveFile(header.Filename, fileHash, int64(len(content)), filePath)
	if err != nil {
		log.Printf("Failed to save file metadata: %v", err)
		http.Error(w, "Failed to save file metadata", http.StatusInternalServerError)
		return
	}
	// Update Bloom filter with file hash
	if !api.Node.GetBloomFilter().SafeTest(fileHash) {
		log.Printf("File hash %s is not in the Bloom filter. Adding it now.", fileHash)
		api.Node.GetBloomFilter().SafeAdd(fileHash)

		// Save updated Bloom filter to database
		if err := api.Node.GetBloomFilter().SaveToDatabase(api.Database, api.Node.GetHost().ID().String()); err != nil {
			log.Printf("Failed to save Bloom filter state for file hash: %v", err)
			http.Error(w, "Failed to update Bloom filter state", http.StatusInternalServerError)
			return
		}
		log.Printf("Bloom filter updated with file hash: %s", fileHash)
	} else {
		log.Printf("File hash %s already exists in the Bloom filter.", fileHash)
	}
	// Create directory to store chunks locally
	chunkDir := fmt.Sprintf("./data/%s", fileHash)
	log.Printf("Creating chunk directory: %s", chunkDir)
	if err := os.MkdirAll(chunkDir, 0755); err != nil {
		log.Printf("Failed to create chunk directory %s: %v", chunkDir, err)
		http.Error(w, "Failed to create chunk directory", http.StatusInternalServerError)
		return
	}
	// Get the TCP port of the node
	tcpPort := api.Node.GetTCPPort()
	ip := "127.0.0.1" // Replace this with the actual IP address of the node, if dynamic

	// Check the size of the peer list
	peerCount := len(api.Node.GetDHT().RoutingTable().ListPeers())
	log.Printf("Number of peers in the network: %d", peerCount)

	// Split and save chunks
	for i := 0; i < totalChunks; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if end > len(content) {
			end = len(content)
		}
		chunk := content[start:end]

		// Compute hash for the chunk
		rawHash := fmt.Sprintf("%x", sha256.Sum256(chunk))
		chunkHash := fmt.Sprintf("%d_%s", i+1, rawHash) // Prepend chunk order
		chunkPath := fmt.Sprintf("%s/%s", chunkDir, chunkHash)

		// Save the chunk locally
		if err := os.WriteFile(chunkPath, chunk, 0644); err != nil {
			log.Printf("Error saving chunk %d: %v", i, err)
			http.Error(w, "Failed to save chunks locally", http.StatusInternalServerError)
			return
		}

		// Save chunk metadata in the database
		err = api.Database.SaveChunk(fileHash, chunkHash, int64(len(chunk)), i+1)
		if err != nil {
			log.Printf("Failed to save chunk metadata: %v", err)
			http.Error(w, "Failed to save chunk metadata", http.StatusInternalServerError)
			return
		}
		log.Printf("Saved chunk metadata: FileHash=%s, ChunkHash=%s, Size=%d \n", fileHash, chunkHash, len(chunk))
		// Update Bloom filter with chunk hash
		if !api.Node.GetBloomFilter().SafeTest(chunkHash) {
			log.Printf("Chunk hash %s is not in the Bloom filter. Adding it now.", chunkHash)
			api.Node.GetBloomFilter().SafeAdd(chunkHash)

			// Save updated Bloom filter to database
			if err := api.Node.GetBloomFilter().SaveToDatabase(api.Database, api.Node.GetHost().ID().String()); err != nil {
				log.Printf("Failed to save Bloom filter state for chunk hash: %v", err)
				http.Error(w, "Failed to update Bloom filter state", http.StatusInternalServerError)
				return
			}
			log.Printf("Bloom filter updated with chunk hash: %s", chunkHash)
		} else {
			log.Printf("Chunk hash %s already exists in the Bloom filter.", chunkHash)
		}
		// Advertise the chunk in the DHT
		chunkCID := cid.NewCidV1(cid.Raw, []byte(chunkHash))
		if err := api.Node.GetDHT().Provide(context.Background(), chunkCID, true); err != nil {
			log.Printf("Failed to announce chunk %s as provided: %v", chunkHash, err)
		} else {
			log.Printf("Announced chunk %s as provided", chunkHash)
		}

		// Broadcast chunk metadata if more than 1 node in the network
		if peerCount > 0 {
			message := map[string]interface{}{
				"hash":      chunkHash,
				"filename":  header.Filename,
				"size":      int64(len(chunk)),
				"fileHash":  fileHash,
				"chunkPath": chunkPath,
				"ip":        ip,
				"tcpPort":   tcpPort,
			}
			msgData, _ := json.Marshal(message)
			api.Node.GetBroadcast().BroadcastMessage(context.Background(), string(msgData))
			log.Printf("Broadcasting chunk %d (%s) to the network", i, chunkHash)
		} else {
			log.Printf("Storing chunk %d (%s) locally, no other nodes in the network", i, chunkHash)
		}
	}

	// Respond with success
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":      "File uploaded successfully",
		"file_hash":    fileHash,
		"total_chunks": totalChunks,
	})
}

func (api *API) DownloadFileHandler(w http.ResponseWriter, r *http.Request) {
	fileHash := r.URL.Query().Get("hash")
	if fileHash == "" {
		http.Error(w, "Missing file hash", http.StatusBadRequest)
		return
	}

	// Retrieve file metadata from the database
	filename, _, chunkDir, err := api.Database.GetFile(fileHash)
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}

	// Retrieve chunk metadata
	chunks, err := api.Database.GetChunks(fileHash)
	if err != nil {
		http.Error(w, "Failed to retrieve chunk metadata", http.StatusInternalServerError)
		return
	}

	// Collect all chunks in the correct order
	var fileContent []byte
	for _, chunk := range chunks {
		chunkPath := fmt.Sprintf("%s/%s", chunkDir, chunk.ChunkHash)

		// Check if chunk is available locally
		if _, err := os.Stat(chunkPath); err == nil {
			// Read the chunk locally
			chunkData, err := os.ReadFile(chunkPath)
			if err != nil {
				log.Printf("Failed to read chunk %s: %v", chunk.ChunkHash, err)
				http.Error(w, "Failed to read chunk locally", http.StatusInternalServerError)
				return
			}
			fileContent = append(fileContent, chunkData...)
		} else {
			// Request the chunk from the network
			log.Printf("Chunk %s not found locally. Requesting from peers...", chunk.ChunkHash)
			chunkData, err := api.Node.RequestChunkFromPeers(chunk.ChunkHash, fileHash, int(chunk.ChunkIndex), api.Database)
			if err != nil {
				log.Printf("Failed to retrieve chunk %s from peers: %v", chunk.ChunkHash, err)
				http.Error(w, "Failed to retrieve chunk from network", http.StatusInternalServerError)
				return
			}
			fileContent = append(fileContent, chunkData...)
		}
	}

	// Serve the reconstructed file
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	w.WriteHeader(http.StatusOK)
	w.Write(fileContent)
}

// Start starts the API server.
func (api *API) Start(port int) {
	http.HandleFunc("/upload", api.UploadFileHandler)
	http.HandleFunc("/download", api.DownloadFileHandler)

	log.Printf("API server listening on port %d", port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", port), nil))
}
