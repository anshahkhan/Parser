package sysmon

import (
	"encoding/xml"
	"errors"
	"fmt"
)

// Sysmon XML structure for event parsing
type Event2 struct {
	XMLName   xml.Name  `xml:"Event"`
	System    System    `xml:"System"`
	EventData EventData `xml:"EventData"`
}

type System2 struct {
	EventID     int    `xml:"EventID"`
	Computer    string `xml:"Computer"`
	TimeCreated struct {
		SystemTime string `xml:"SystemTime,attr"`
	} `xml:"TimeCreated"`
}

type EventData2 struct {
	Data []DataItem `xml:"Data"`
}

type DataItem2 struct {
	Name  string `xml:"Name,attr"`
	Value string `xml:",chardata"`
}

// ParseEvent2 parses Sysmon Event ID 2
func ParseEvent2(log map[string]interface{}) (map[string]interface{}, error) {
	rawXML, ok := extractXMLFromLog(log)
	if !ok {
		return nil, errors.New("missing 'winlog.event_data.Xml' for parsing event 2")
	}

	var event Event
	err := xml.Unmarshal([]byte(rawXML), &event)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal XML: %w", err)
	}

	values := make(map[string]string)
	for _, item := range event.EventData.Data {
		values[item.Name] = item.Value
	}

	parsed := map[string]interface{}{
		"event_id":   event.System.EventID,
		"event_name": "File Creation Time Changed",
		"source":     "sysmon",
		"timestamp":  event.System.TimeCreated.SystemTime,
		"agent": map[string]string{
			"hostname": event.System.Computer,
		},
		"fields": map[string]interface{}{
			"file": map[string]interface{}{
				"target_filename": values["TargetFilename"],
				"creation_utc":    values["CreationUtcTime"],
				"previous_utc":    values["PreviousCreationUtcTime"],
			},
		},
		"tags":      []string{"sysmon", "event2", "file_creation_time_changed"},
		"parsed_by": "shahdec-parser",
		"status":    "parsed",
	}

	return parsed, nil
}
