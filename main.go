package main

import (
	"context"
	"ddb/config"
	"ddb/internal/api"
	"ddb/internal/database"
	"ddb/internal/node"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
)

func main() {

	config.LoadConfig()
	nodeConfig := config.AppConfig.Node
	if nodeConfig.Port == 0 {
		log.Fatal("Port is required. Use -port flag to specify.")
	}

	// Create the context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize components
	//database := database.NewDatabase(*dbHost, *dbPort, *dbUser, *dbPassword, *dbName)
	db := database.NewDatabase(
		config.AppConfig.Database.Host,
		fmt.Sprintf("%d", config.AppConfig.Database.Port),
		config.AppConfig.Database.User,
		config.AppConfig.Database.Password,
		config.AppConfig.Database.DBName,
	)

	//node := node.NewNode(ctx, *port, *tcpPort, db)
	n := node.NewNode(context.Background(), nodeConfig.Port, nodeConfig.TCPPort, db)

	api := api.NewAPI(n, db)
	graphqlServer := api.NewGraphQLServer()
	// Start handling incoming metadata
	go n.Broadcast.HandleIncomingMetadata(ctx, n, db)
	// Periodic DHT logging
	go n.PeriodicDHTLogging(ctx)

	// Periodic DHT bootstrap
	go n.PeriodicDHTBootstrap(ctx)

	// Connect to bootstrap peer if provided
	if nodeConfig.Bootstrap != "" {
		n.ConnectToPeer(ctx, nodeConfig.Bootstrap)

		// Extract IP and TCP port from bootstrap
		bootstrapParts := strings.Split(nodeConfig.Bootstrap, "/")
		if len(bootstrapParts) < 7 {
			log.Fatal("Invalid bootstrap format. Expected format: /ip4/<IP>/tcp/<Port>/p2p/<PeerID>")
		}
		bootstrapIP := bootstrapParts[2]
		bootstrapPort := bootstrapParts[4]
		bootstrapPeerID := bootstrapParts[6]
		bootstrapTCPAddr := fmt.Sprintf("%s:%s", bootstrapIP, bootstrapPort)

		// Sync from bootstrap peer
		log.Printf("Bootstrap IP: %s, Port: %s, Peer ID: %s", bootstrapIP, bootstrapPort, bootstrapPeerID)
		if err := n.SyncFromPeer(nodeConfig.Bootstrap, bootstrapTCPAddr); err != nil {
			log.Fatalf("Sync process failed: %v", err)
		}
		log.Println("Sync process completed successfully.")
	}

	// Start the TCP Server for chunk transfer
	go n.StartTCPServer()

	// Start the API server
	//go api.Start(*apiPort)

	go graphqlServer.ServeGraphQL(nodeConfig.GraphQLPort)
	// Wait for termination signal
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)
	<-ch
	// Save Bloom filter state and block until it's saved
	if err := n.SaveBloomStateBlocking(); err != nil {
		log.Fatalf("Failed to save Bloom filter state: %v", err)
	}
	log.Println("Shutting down...")
}
