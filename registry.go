package main

import (
	"errors"
	"fmt"
	//"github.com/anshahkhan/Parser/sysmon"
)

// ParsedLog defines the unified output structure
type ParsedLog struct {
	EventID   int                    `json:"event_id"`
	EventName string                 `json:"event_name"`
	Source    string                 `json:"source"`
	Timestamp string                 `json:"timestamp"`
	Fields    map[string]interface{} `json:"fields"`
	Agent     map[string]string      `json:"agent"`
	Tags      []string               `json:"tags"`
	ParsedBy  string                 `json:"parsed_by"`
	Status    string                 `json:"status"`
}

// parserFunc defines the function signature for all event parsers
type parserFunc func(map[string]interface{}) (ParsedLog, error)

// registry maps log sources to event-specific parser functions
var registry = map[string]map[int]parserFunc{
	"sysmon": {
		//	1: sysmon.ParseEvent1,
		//	3: sysmon.ParseEvent3,
		// Add more as needed
	},
}

// RouteLog routes an incoming log to the appropriate parser
func RouteLog(log map[string]interface{}) (ParsedLog, error) {
	source, err := detectSource(log)
	if err != nil {
		return ParsedLog{}, err
	}

	eventID, err := extractEventID(log, source)
	if err != nil {
		return ParsedLog{}, err
	}

	parserMap, ok := registry[source]
	if !ok {
		return ParsedLog{}, fmt.Errorf("no parsers registered for source: %s", source)
	}

	parserFunc, ok := parserMap[eventID]
	if !ok {
		return ParsedLog{}, fmt.Errorf("no parser found for event_id %d under source %s", eventID, source)
	}

	return parserFunc(log)
}

// detectSource attempts to determine the log source (sysmon, windows, etc.)
func detectSource(log map[string]interface{}) (string, error) {
	if _, ok := log["winlog"]; ok {
		return "sysmon", nil
	}
	if _, ok := log["eventdata"]; ok {
		return "windows", nil
	}
	return "", errors.New("unable to detect log source")
}

// extractEventID pulls out the event ID from the log
func extractEventID(log map[string]interface{}, source string) (int, error) {
	switch source {
	case "sysmon":
		winlog, ok := log["winlog"].(map[string]interface{})
		if !ok {
			return 0, errors.New("invalid winlog format")
		}
		system, ok := winlog["system"].(map[string]interface{})
		if !ok {
			return 0, errors.New("missing system block in winlog")
		}
		eid, ok := system["event_id"].(float64) // JSON numbers come in as float64
		if !ok {
			return 0, errors.New("event_id not found or invalid")
		}
		return int(eid), nil

	default:
		return 0, errors.New("unsupported source for event_id extraction")
	}
}
