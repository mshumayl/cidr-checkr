package main

import (
	"cidr_checkr/internal/handlers"
	"fmt"
	"log"
	"net/http"
)

func main() {
	router := http.NewServeMux()

	// Register handlers
	router.HandleFunc("/api/analyze-cidrs", handlers.AnalyzeCIDRs)

	fmt.Println("Starting server on :8080")
	log.Fatal(http.ListenAndServe(":8080", router))
}
