package broadcast

import (
	"context"
	"ddb/internal/database"
	"ddb/internal/utils"
	"encoding/json"
	"fmt"
	"log"
	"os"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/host"
)

// Define an interface that `node.Node` will implement
type NodeInterface interface {
	RequestChunkFromNode(chunkHash string, peerAddr string) ([]byte, error)
}

type Broadcast struct {
	PubSub *pubsub.PubSub
	Topic  *pubsub.Topic
}

// NewBroadcast initializes the pubsub service and joins the topic.
func NewBroadcast(ctx context.Context, host host.Host, topicName string) *Broadcast {
	pubSub, err := pubsub.NewGossipSub(ctx, host)
	if err != nil {
		log.Fatalf("Failed to create pubsub: %v", err)
	}

	topic, err := pubSub.Join(topicName)
	if err != nil {
		log.Fatalf("Failed to join topic: %v", err)
	}

	log.Printf("Subscribed to topic: %s", topicName)
	return &Broadcast{PubSub: pubSub, Topic: topic}
}

// BroadcastMessage publishes a message to the topic.
func (b *Broadcast) BroadcastMessage(ctx context.Context, message string) {
	err := b.Topic.Publish(ctx, []byte(message))
	if err != nil {
		log.Printf("Failed to publish message: %v", err)
	} else {
		log.Printf("Broadcasted message: %s", message)
	}
}

func (b *Broadcast) HandleIncomingMetadata(ctx context.Context, n NodeInterface, database *database.Database) {
	subscription, err := b.Topic.Subscribe()
	if err != nil {
		log.Fatalf("Failed to subscribe to topic: %v", err)
	}

	for {
		msg, err := subscription.Next(ctx)
		if err != nil {
			log.Printf("Failed to read pubsub message: %v", err)
			continue
		}

		// Parse the metadata
		var metadata struct {
			FileHash   string `json:"fileHash"`
			ChunkHash  string `json:"hash"`
			Filename   string `json:"filename"`
			ChunkIndex int    `json:chunkIndex`
			Size       int64  `json:"size"`
			IP         string `json:"ip"`
			Port       int    `json:"tcpPort"`
		}
		if err := json.Unmarshal(msg.Data, &metadata); err != nil {
			log.Printf("Failed to parse metadata: %v", err)
			continue
		}

		log.Printf("Received metadata for file: %s (fileHash: %s, chunkHash: %s, size: %d, node: %s:%d)",
			metadata.Filename, metadata.FileHash, metadata.ChunkHash, metadata.Size, metadata.IP, metadata.Port)
		// Save file metadata if not already present
		if !database.FileExists(metadata.FileHash) {
			log.Printf("File metadata for %s not found. Saving it now...", metadata.FileHash)
			//filePath := fmt.Sprintf("./data/%s", )
			filePath := fmt.Sprintf("%s/data/%s", utils.GetRootPath(), metadata.FileHash)
			if err := database.SaveFile(metadata.Filename, metadata.FileHash, metadata.Size, filePath); err != nil {
				log.Printf("Failed to save file metadata for %s: %v", metadata.FileHash, err)
				continue
			}
			if err := database.SaveFileEmbedding(metadata.FileHash); err != nil {
				log.Printf("Failed to save file metadata for %s: %v", metadata.FileHash, err)
				continue
			}
			log.Printf("File %s metadata saved successfully.", metadata.FileHash)
		}

		// Ensure the `./data/<fileHash>` directory exists
		//chunkDir := fmt.Sprintf("./data/%s", metadata.FileHash)
		chunkDir := fmt.Sprintf("%s/data/%s", utils.GetRootPath(), metadata.FileHash)
		if _, err := os.Stat(chunkDir); os.IsNotExist(err) {
			log.Printf("Directory %s does not exist. Creating it...", chunkDir)
			if err := os.MkdirAll(chunkDir, 0755); err != nil {
				log.Printf("Failed to create directory %s: %v", chunkDir, err)
				continue
			}
		}

		// Check if the chunk already exists locally
		chunkPath := fmt.Sprintf("%s/%s", chunkDir, metadata.ChunkHash)
		if _, err := os.Stat(chunkPath); err == nil {
			log.Printf("Chunk %s already exists locally. Skipping download.", metadata.ChunkHash)
			continue
		}

		log.Printf("Chunk %s not found locally. Attempting to fetch via TCP from %s:%d...",
			metadata.ChunkHash, metadata.IP, metadata.Port)

		// Construct peer address
		peerAddr := fmt.Sprintf("%s:%d", metadata.IP, metadata.Port)

		// Fetch chunk via TCP
		chunkData, err := n.RequestChunkFromNode(metadata.ChunkHash, peerAddr)
		if err != nil {
			log.Printf("Failed to retrieve chunk %s via TCP from %s: %v", metadata.ChunkHash, peerAddr, err)
			continue
		}

		// Save the chunk locally
		if err := os.WriteFile(chunkPath, chunkData, 0644); err != nil {
			log.Printf("Failed to save chunk %s: %v", metadata.ChunkHash, err)
			continue
		}

		// Save chunk metadata to the database
		err = database.SaveChunk(metadata.FileHash, metadata.ChunkHash, metadata.Size, metadata.ChunkIndex)
		if err != nil {
			log.Printf("Failed to save chunk metadata for %s: %v", metadata.ChunkHash, err)
		} else {
			log.Printf("Stored chunk %s locally after broadcast.", metadata.ChunkHash)
		}

	}
}
