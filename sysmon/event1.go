package sysmon

import (
	"encoding/xml"
	"errors"
	"fmt"
)

// Sysmon XML structure
type Event struct {
	XMLName   xml.Name  `xml:"Event"`
	System    System    `xml:"System"`
	EventData EventData `xml:"EventData"`
}

type System struct {
	EventID     int    `xml:"EventID"`
	Computer    string `xml:"Computer"`
	TimeCreated struct {
		SystemTime string `xml:"SystemTime,attr"`
	} `xml:"TimeCreated"`
}

type EventData struct {
	Data []DataItem `xml:"Data"`
}

type DataItem struct {
	Name  string `xml:"Name,attr"`
	Value string `xml:",chardata"`
}

// ParseEvent1 parses Sysmon Event ID 1
func ParseEvent1(log map[string]interface{}) (map[string]interface{}, error) {
	// Ensure "winlog.event_data.Xml" exists
	rawXML, ok := extractXMLFromLog(log)
	if !ok {
		return nil, errors.New("missing 'winlog.event_data.Xml' for parsing event 1")
	}

	var event Event
	err := xml.Unmarshal([]byte(rawXML), &event)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal XML: %w", err)
	}

	// Extract values from EventData
	values := make(map[string]string)
	for _, item := range event.EventData.Data {
		values[item.Name] = item.Value
	}

	parsed := map[string]interface{}{
		"event_id":   event.System.EventID,
		"event_name": "Process Create",
		"source":     "sysmon",
		"timestamp":  event.System.TimeCreated.SystemTime,
		"agent": map[string]string{
			"hostname": event.System.Computer,
		},
		"fields": map[string]interface{}{
			"user": values["User"],
			"process": map[string]interface{}{
				"id":                values["ProcessId"],
				"guid":              values["ProcessGuid"],
				"image":             values["Image"],
				"command_line":      values["CommandLine"],
				"current_directory": values["CurrentDirectory"],
			},
			"parent": map[string]interface{}{
				"id":           values["ParentProcessId"],
				"image":        values["ParentImage"],
				"command_line": values["ParentCommandLine"],
			},
		},
		"tags":      []string{"sysmon", "event1", "process_create"},
		"parsed_by": "shahdec-parser",
		"status":    "parsed",
	}

	return parsed, nil
}

// extractXMLFromLog is a helper to pull embedded XML from log
func extractXMLFromLog(log map[string]interface{}) (string, bool) {
	winlog, ok := log["winlog"].(map[string]interface{})
	if !ok {
		return "", false
	}

	eventData, ok := winlog["event_data"].(map[string]interface{})
	if !ok {
		return "", false
	}

	xmlStr, ok := eventData["Xml"].(string)
	return xmlStr, ok
}
