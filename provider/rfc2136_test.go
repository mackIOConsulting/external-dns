package provider

import (
	"fmt"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestSimpleCall(t *testing.T) {
	m := new(dns.Msg)
	m.SetQuestion("*", dns.TypeANY)
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

	m := new(dns.Msg)
	m.SetUpdate("localhost.")
	m.Id = 1234

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
