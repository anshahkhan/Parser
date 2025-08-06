package main

import (
	"errors"
	"fmt"

	"github.com/anshahkhan/Parser/sysmon"
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
		1: wrapSysmonParser(sysmon.ParseEvent1),
		// other sysmon event parsers here...
	},
}

// wrapSysmonParser adapts a sysmon parser to match parserFunc type
func wrapSysmonParser(f func(map[string]interface{}) (map[string]interface{}, error)) parserFunc {
	return func(log map[string]interface{}) (ParsedLog, error) {
		parsedMap, err := f(log)
		if err != nil {
			return ParsedLog{}, err
		}

		return ParsedLog{
			EventID:   toInt(parsedMap["event_id"]),
			EventName: toString(parsedMap["event_name"]),
			Source:    toString(parsedMap["source"]),
			Timestamp: toString(parsedMap["timestamp"]),
			Fields:    toMap(parsedMap["fields"]),
			Agent:     toMapString(parsedMap["agent"]),
			Tags:      toStringSlice(parsedMap["tags"]),
			ParsedBy:  toString(parsedMap["parsed_by"]),
			Status:    toString(parsedMap["status"]),
		}, nil
	}
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

// Helpers for type conversions
func toString(val interface{}) string {
	if str, ok := val.(string); ok {
		return str
	}
	return ""
}

func toInt(val interface{}) int {
	if f, ok := val.(float64); ok {
		return int(f)
	}
	if i, ok := val.(int); ok {
		return i
	}
	return 0
}

func toMap(val interface{}) map[string]interface{} {
	if m, ok := val.(map[string]interface{}); ok {
		return m
	}
	return map[string]interface{}{}
}

func toMapString(val interface{}) map[string]string {
	if m, ok := val.(map[string]string); ok {
		return m
	}
	return map[string]string{}
}

func toStringSlice(val interface{}) []string {
	if s, ok := val.([]string); ok {
		return s
	}
	return []string{}
}

// detectSource determines log source (sysmon/windows)
func detectSource(log map[string]interface{}) (string, error) {
	if _, ok := log["winlog"]; ok {
		return "sysmon", nil
	}
	if _, ok := log["eventdata"]; ok {
		return "windows", nil
	}
	return "", errors.New("unable to detect log source")
}

// extractEventID extracts event_id based on source
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
		eid, ok := system["event_id"].(float64)
		if !ok {
			return 0, errors.New("event_id not found or invalid")
		}
		return int(eid), nil

	default:
		return 0, errors.New("unsupported source for event_id extraction")
	}
}
