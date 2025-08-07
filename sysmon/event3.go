package sysmon

import (
	"encoding/xml"
	"errors"
	"fmt"
)

// Sysmon XML structure for Event ID 3 (Network Connection)
type Event3 struct {
	XMLName   xml.Name   `xml:"Event"`
	System    System3    `xml:"System"`
	EventData EventData3 `xml:"EventData"`
}

type System3 struct {
	EventID     int    `xml:"EventID"`
	Computer    string `xml:"Computer"`
	TimeCreated struct {
		SystemTime string `xml:"SystemTime,attr"`
	} `xml:"TimeCreated"`
}

type EventData3 struct {
	Data []DataItem3 `xml:"Data"`
}

type DataItem3 struct {
	Name  string `xml:"Name,attr"`
	Value string `xml:",chardata"`
}

// ParseEvent3 parses Sysmon Event ID 3 logs
func ParseEvent3(log map[string]interface{}) (map[string]interface{}, error) {
	rawXML, ok := extractXMLFromLog(log)
	if !ok {
		return nil, errors.New("missing 'winlog.event_data.Xml' for parsing event 3")
	}

	var event Event3
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
		"event_name": "Network Connection Detected",
		"source":     "sysmon",
		"timestamp":  event.System.TimeCreated.SystemTime,
		"agent": map[string]string{
			"hostname": event.System.Computer,
		},
		"fields": map[string]interface{}{
			"network": map[string]interface{}{
				"protocol":         values["Protocol"],
				"source_ip":        values["SourceIp"],
				"source_port":      values["SourcePort"],
				"destination_ip":   values["DestinationIp"],
				"destination_port": values["DestinationPort"],
				"initiated":        values["Initiated"],
			},
			"process": map[string]interface{}{
				"image": values["Image"],
				"pid":   values["ProcessId"],
				"user":  values["User"],
			},
		},
		"tags":      []string{"sysmon", "event3", "network_connection"},
		"parsed_by": "shahdec-parser",
		"status":    "parsed",
	}

	return parsed, nil
}
