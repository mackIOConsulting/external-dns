/*
Copyright 2017 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package provider

import (
	"time"

	"github.com/kubernetes-incubator/external-dns/endpoint"
	"github.com/kubernetes-incubator/external-dns/plan"
	"github.com/miekg/dns"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

var (
	tsigAlgs = map[string]string{
		"hmac-md5":    dns.HmacMD5,
		"hmac-sha1":   dns.HmacSHA1,
		"hmac-sha256": dns.HmacSHA256,
		"hmac-sha512": dns.HmacSHA512,
	}
)

type rfc2136Provider struct {
	client *dns.Client
	conf   RFC2136Config
}

// RFC2136Config RFC2136 provider config
type RFC2136Config struct {
	DNSServerHost   string
	MainWorkingZone string
	TSIGSecret      string
	TSIGSecretAlg   string
	TSIGSecretName  string
	TSIGFurge       uint16
}

// NewRFC2136Provider initializes a new RFC2136 based provider
func NewRFC2136Provider(config RFC2136Config) (Provider, error) {
	if e, ok := tsigAlgs[config.TSIGSecretAlg]; !ok {
		return nil, errors.Errorf("%s is not supported TSIG algorithm", config.TSIGSecretAlg)
	} else {
		config.TSIGSecretAlg = e
	}

	c := new(dns.Client)

	config.MainWorkingZone = ensureTrailingDot(config.MainWorkingZone)
	secretName := ensureTrailingDot(config.TSIGSecretName)
	config.TSIGSecretName = secretName
	c.TsigSecret = map[string]string{
		secretName: config.TSIGSecret,
	}

	return &rfc2136Provider{
		client: c,
		conf:   config,
	}, nil
}

// Records retuns a list of endpoints in a given zone
func (p *rfc2136Provider) Records() (endpoints []*endpoint.Endpoint, _ error) {
	return []*endpoint.Endpoint{}, nil
}

func createRRSlice(endpoints []*endpoint.Endpoint) ([]dns.RR, error) {
	var err error
	insertRecords := make([]dns.RR, len(endpoints))
	for i, c := range endpoints {
		insertRecords[i], err = dns.NewRR(c.String())
		if err != nil {
			return nil, err
		}
	}
	return insertRecords, nil
}

// ApplyChanges applies a given set of changes
func (p *rfc2136Provider) ApplyChanges(changes *plan.Changes) error {

	m := new(dns.Msg)
	m.SetUpdate(p.conf.MainWorkingZone)
	endpoints := make([]*endpoint.Endpoint, 0)
	baseFields := log.WithFields(log.Fields{
		"provider": "rfc2136",
		"host":     p.conf.DNSServerHost,
		"zone":     p.conf.MainWorkingZone,
	})

	if changes.Delete != nil {
		endpoints = append(endpoints, changes.Delete...)
	}
	if changes.Create != nil {
		endpoints = append(endpoints, changes.Create...)
	}
	if changes.UpdateNew != nil {
		endpoints = append(endpoints, changes.UpdateNew...)
	}
	if changes.UpdateOld != nil {
		endpoints = append(endpoints, changes.UpdateOld...)
	}

	updateRecords, err := createRRSlice(endpoints)
	if err != nil {
		return err
	}
	for _, e := range updateRecords {
		baseFields.WithFields(log.Fields{
			"record": e.String(),
		}).Debug("adding new record")
	}

	m.Insert(updateRecords)
	m.SetTsig(p.conf.TSIGSecretName, p.conf.TSIGSecretAlg, p.conf.TSIGFurge, time.Now().Unix())

	r, rtt, err := p.client.Exchange(m, p.conf.DNSServerHost)
	if err != nil {
		return err
	}

	baseFields.WithFields(log.Fields{
		"time":   rtt,
		"result": r,
	}).Info("exchange finished")

	if r != nil && r.Rcode != dns.RcodeSuccess {
		return errors.Errorf("failed to get an valid answer\n%v", r)
	}

	return nil
}
