package digitalocean

import (
	"testing"
	"time"

	"github.com/digitalocean/godo"
	"github.com/libdns/libdns"
)

// DigitalOcean expects the priority, port, weight, flags and tag of a record in
// dedicated request fields rather than in `data`, while libdns.RR.Data holds the
// complete RDATA. These tests cover the split on write.
//
// They deliberately do not go through fromGodo, so they are independent of the
// read-direction fix in #19.

func TestRecordToGoDoSplitsRDATAFromTypedRecords(t *testing.T) {
	tests := []struct {
		name   string
		record libdns.Record
		want   godo.DomainRecordEditRequest
	}{
		{
			name:   "A is unaffected",
			record: libdns.RR{Name: "www", Type: "A", Data: "192.0.2.1", TTL: time.Hour},
			want:   godo.DomainRecordEditRequest{Name: "www", Type: "A", Data: "192.0.2.1", TTL: 3600},
		},
		{
			name:   "TXT is unaffected",
			record: libdns.TXT{Name: "txt", TTL: time.Hour, Text: "hello world"},
			want:   godo.DomainRecordEditRequest{Name: "txt", Type: "TXT", Data: "hello world", TTL: 3600},
		},
		{
			name:   "MX preference goes to the priority field",
			record: libdns.MX{Name: "@", TTL: time.Hour, Preference: 10, Target: "mail.example.com."},
			want:   godo.DomainRecordEditRequest{Name: "@", Type: "MX", Data: "mail.example.com.", Priority: 10, TTL: 3600},
		},
		{
			name: "SRV numbers go to their own fields and the owner name is reassembled",
			record: libdns.SRV{
				Service: "sip", Transport: "tcp", Name: "example", TTL: time.Hour,
				Priority: 10, Weight: 20, Port: 5060, Target: "sip.example.com.",
			},
			want: godo.DomainRecordEditRequest{
				Name: "_sip._tcp.example", Type: "SRV", Data: "sip.example.com.",
				Priority: 10, Weight: 20, Port: 5060, TTL: 3600,
			},
		},
		{
			name:   "CAA flags and tag go to their own fields",
			record: libdns.CAA{Name: "@", TTL: time.Hour, Flags: 128, Tag: "iodef", Value: "mailto:security@example.com"},
			want:   godo.DomainRecordEditRequest{Name: "@", Type: "CAA", Data: "mailto:security@example.com", Flags: 128, Tag: "iodef", TTL: 3600},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := recordToGoDo(tt.record)
			if err != nil {
				t.Fatalf("recordToGoDo() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("recordToGoDo() =\n  %+v\nwant\n  %+v", got, tt.want)
			}
		})
	}
}

func TestRecordToGoDoSplitsRDATAFromOpaqueRR(t *testing.T) {
	// A caller may hand us an opaque RR whose Data is already full RDATA — which
	// is also what fromGodo produces once #19 lands. The split must work from
	// that form too, not just from the typed structs.
	tests := []struct {
		rr   libdns.RR
		want godo.DomainRecordEditRequest
	}{
		{
			rr:   libdns.RR{Name: "@", Type: "MX", Data: "10 mail.example.com.", TTL: time.Hour},
			want: godo.DomainRecordEditRequest{Name: "@", Type: "MX", Data: "mail.example.com.", Priority: 10, TTL: 3600},
		},
		{
			rr: libdns.RR{Name: "_sip._tcp.example", Type: "SRV", Data: "10 20 5060 sip.example.com.", TTL: time.Hour},
			want: godo.DomainRecordEditRequest{
				Name: "_sip._tcp.example", Type: "SRV", Data: "sip.example.com.",
				Priority: 10, Weight: 20, Port: 5060, TTL: 3600,
			},
		},
		{
			rr:   libdns.RR{Name: "@", Type: "CAA", Data: `0 issue "letsencrypt.org"`, TTL: time.Hour},
			want: godo.DomainRecordEditRequest{Name: "@", Type: "CAA", Data: "letsencrypt.org", Tag: "issue", TTL: 3600},
		},
	}

	for _, tt := range tests {
		t.Run(tt.rr.Type, func(t *testing.T) {
			got, err := recordToGoDo(tt.rr)
			if err != nil {
				t.Fatalf("recordToGoDo() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("recordToGoDo() =\n  %+v\nwant\n  %+v", got, tt.want)
			}
		})
	}
}

func TestRecordToGoDoRejectsMalformedRDATA(t *testing.T) {
	// Previously these were sent to the API verbatim in `data`, with priority,
	// port, weight, flags and tag all left at zero.
	for _, rr := range []libdns.RR{
		{Name: "@", Type: "MX", Data: "not-a-preference", TTL: time.Hour},
		{Name: "_sip._tcp", Type: "SRV", Data: "incomplete", TTL: time.Hour},
		{Name: "@", Type: "MX", Data: "", TTL: time.Hour},
	} {
		t.Run(rr.Type+"/"+rr.Data, func(t *testing.T) {
			if _, err := recordToGoDo(rr); err == nil {
				t.Errorf("recordToGoDo(%q) accepted a malformed %s record, want an error", rr.Data, rr.Type)
			}
		})
	}
}
