package digitalocean

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/digitalocean/godo"
	"github.com/libdns/libdns"
)

// DNS custom struct that implements the libdns.Record interface and keeps the ID field used internally
type DNS struct {
	Record libdns.RR
	ID     string
}

func (d DNS) RR() libdns.RR {
	return d.Record
}

// fromRecord creates a dns struct from a libdns.Record, with an optional ID
func fromRecord(record libdns.Record, id string) DNS {
	rr := record.RR()
	return DNS{
		Record: rr,
		ID:     id,
	}
}

// fromGodo creates a dns struct from godo.DomainRecord
func fromGodo(entry godo.DomainRecord) DNS {
	return DNS{
		Record: libdns.RR{
			Name: entry.Name,
			Data: dataFromGodo(entry),
			Type: entry.Type,
			TTL:  time.Duration(entry.TTL) * time.Second,
		},
		ID: strconv.Itoa(entry.ID),
	}
}

// dataFromGodo rebuilds the zone file representation of the record data because DO returns priority, weight, port etc. in separate fields
func dataFromGodo(entry godo.DomainRecord) string {
	switch entry.Type {
	case "MX":
		return libdns.MX{
			Preference: uint16(entry.Priority),
			Target:     entry.Data,
		}.RR().Data
	case "SRV":
		return libdns.SRV{
			Priority: uint16(entry.Priority),
			Weight:   uint16(entry.Weight),
			Port:     uint16(entry.Port),
			Target:   entry.Data,
		}.RR().Data
	case "CAA":
		return libdns.CAA{
			Flags: uint8(entry.Flags),
			Tag:   entry.Tag,
			Value: entry.Data,
		}.RR().Data
	default:
		return entry.Data
	}
}

// recordToGoDo converts a libdns.RR to the DigitalOcean API format.
//
// DigitalOcean expects the priority of an MX or SRV record, the port and weight
// of an SRV record, and the flags and tag of a CAA record in dedicated request
// fields, not in Data. libdns.RR.Data holds the complete RDATA, so those parts
// are split back out of it here.
//
// The record is parsed rather than the string split by hand, so a malformed
// value is reported instead of being sent as a Data the API would reject or
// silently misread.
func recordToGoDo(record libdns.Record) (godo.DomainRecordEditRequest, error) {
	rr := record.RR()

	req := godo.DomainRecordEditRequest{
		Name: rr.Name,
		Data: rr.Data,
		Type: rr.Type,
		TTL:  int(rr.TTL.Seconds()),
	}

	switch rr.Type {
	case "MX", "SRV", "CAA":
	default:
		return req, nil
	}

	parsed, err := rr.Parse()
	if err != nil {
		return req, fmt.Errorf("parsing %s record %q: %w", rr.Type, rr.Name, err)
	}

	switch v := parsed.(type) {
	case libdns.MX:
		req.Priority = int(v.Preference)
		req.Data = v.Target
	case libdns.SRV:
		req.Priority = int(v.Priority)
		req.Weight = int(v.Weight)
		req.Port = int(v.Port)
		req.Data = v.Target
		// libdns splits the service and transport labels out of the owner
		// name; DigitalOcean wants them back as part of it.
		req.Name = strings.Trim(fmt.Sprintf("_%s._%s.%s", v.Service, v.Transport, v.Name), ".")
	case libdns.CAA:
		req.Flags = int(v.Flags)
		req.Tag = v.Tag
		req.Data = v.Value
	}

	return req, nil
}

// idFromRecord get the ID from a libdns.Record
func idFromRecord(record libdns.Record) (int, error) {
	var raw string
	if dns, ok := record.(DNS); ok {
		raw = dns.ID
	}
	id, err := strconv.Atoi(raw)
	if err != nil {
		return 0, err
	}
	return id, nil
}
