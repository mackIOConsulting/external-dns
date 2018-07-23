package provider

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/kubernetes-incubator/external-dns/endpoint"
	"github.com/kubernetes-incubator/external-dns/plan"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

var (
	enableIntegrationTests = os.Getenv("EXTERNAL_DNS_RFC2136_INTEGRATION_TESTS")
)

func TestProviderCreateRecords(t *testing.T) {
	if len(enableIntegrationTests) == 0 {
		return
	}
	p, err := NewRFC2136Provider(RFC2136Config{
		DNSServerHost:   "127.0.0.1:53",
		MainWorkingZone: "localhost",
		TSIGSecret:      "WNiF81LrIxYbbPwt/twgUA==",
		TSIGSecretAlg:   "hmac-md5",
		TSIGSecretName:  "rndc-key",
		TSIGFurge:       300,
	})
	assert.NoError(t, err)

	err = p.ApplyChanges(&plan.Changes{
		Create: []*endpoint.Endpoint{
			{
				DNSName:    "boom3.localhost",
				Targets:    []string{"VALUE"},
				RecordType: "TXT",
				RecordTTL:  3600,
			},
		}})
	assert.NoError(t, err)
}

func TestSimpleCall(t *testing.T) {
	if len(enableIntegrationTests) == 0 {
		return
	}
	m := new(dns.Msg)
	m.SetQuestion("localhost.", dns.TypeANY)
	m.SetTsig("rndc-key.", dns.HmacMD5, 0xFFFF, time.Now().Unix())

	c := new(dns.Client)
	c.TsigSecret = map[string]string{
		"rndc-key.": "WNiF81LrIxYbbPwt/twgUA==",
	}

	r, _, err := c.Exchange(m, "127.0.0.1:53")
	if err != nil {
		t.Errorf("failed to exchange: %v", err)
	}

	if r != nil && r.Rcode != dns.RcodeSuccess {
		t.Errorf("failed to get an valid answer\n%v", r)
	}

	for _, e := range r.Answer {
		fmt.Println(e)
	}
}

func TestAddNewEntryCall(t *testing.T) {
	if len(enableIntegrationTests) == 0 {
		return
	}

	m := new(dns.Msg)
	m.SetUpdate("localhost.")

	rr, err := dns.NewRR("boom_2.localhost 3600 txt brrrrrrr")
	assert.NoError(t, err)
	m.Insert([]dns.RR{
		rr,
	})

	m.SetTsig("rndc-key.", dns.HmacMD5, 0xFFFF, time.Now().Unix())

	c := new(dns.Client)

	c.TsigSecret = map[string]string{
		"rndc-key.": "WNiF81LrIxYbbPwt/twgUA==",
	}

	r, _, err := c.Exchange(m, "127.0.0.1:53")
	assert.NoError(t, err)

	if r != nil && r.Rcode != dns.RcodeSuccess {
		fmt.Println(r)
		t.Errorf("failed to get an valid answer\n%v", r)
	}
}
