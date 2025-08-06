package main

import (
	"encoding/json"
	"fmt"
	"os"
)

func main() {
	fmt.Println("ShahDec Parsing Engine initialized 🚀")

	// Load sample log file
	file, err := os.ReadFile("sample_event1.json")
	if err != nil {
		fmt.Println("Failed to read log file:", err)
		return
	}

	var log map[string]interface{}
	err = json.Unmarshal(file, &log)
	if err != nil {
		fmt.Println("Failed to parse JSON:", err)
		return
	}

	// Call the router
	parsed, err := RouteLog(log)
	if err != nil {
		fmt.Println("Failed to parse log:", err)
		return
	}

	// Output the parsed log
	out, _ := json.MarshalIndent(parsed, "", "  ")
	fmt.Println("✅ Parsed Output:")
	fmt.Println(string(out))
}
