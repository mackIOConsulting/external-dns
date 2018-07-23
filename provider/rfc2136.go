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
	"fmt"
	"time"

	"github.com/kubernetes-incubator/external-dns/endpoint"
	"github.com/kubernetes-incubator/external-dns/plan"
	"github.com/miekg/dns"
	"github.com/pkg/errors"
)

var (
	tsigAlgs = map[string]string{
		"hmac-md5":    dns.HmacMD5,
		"hmac-sha1":   dns.HmacSHA1,
		"hmac-sha256": dns.HmacSHA256,
		"hmac-sha512": dns.HmacSHA512,
	}
)

const (
	tsigFudge        = 300
	rfc2136RecordTTL = 3600 // Default TTL of 1 hour if not set
)

//type identityService struct {
//	//service *dnsimple.IdentityService
//}
//
//func (i identityService) Whoami() (*dnsimple.WhoamiResponse, error) {
//	return nil, nil
//	//return i.service.Whoami()
//}

//
//// Returns the account ID given dnsimple credentials
//func (p *dnsimpleProvider) GetAccountID(credentials dnsimple.Credentials, client dnsimple.Client) (accountID string, err error) {
//	// get DNSimple client accountID
//	whoamiResponse, err := client.Identity.Whoami()
//	if err != nil {
//		return "", err
//	}
//	return strconv.Itoa(whoamiResponse.Data.Account.ID), nil
//}

// dnsimpleZoneServiceInterface is an interface that contains all necessary zone services from dnsimple
//type rfc2136ZoneServiceInterface interface {
//	ListZones(accountID string, options *dnsimple.ZoneListOptions) (*dnsimple.ZonesResponse, error)
//	ListRecords(accountID string, zoneID string, options *dnsimple.ZoneRecordListOptions) (*dnsimple.ZoneRecordsResponse, error)
//	CreateRecord(accountID string, zoneID string, recordAttributes dnsimple.ZoneRecord) (*dnsimple.ZoneRecordResponse, error)
//	DeleteRecord(accountID string, zoneID string, recordID int) (*dnsimple.ZoneRecordResponse, error)
//	UpdateRecord(accountID string, zoneID string, recordID int, recordAttributes dnsimple.ZoneRecord) (*dnsimple.ZoneRecordResponse, error)
//}
//
//type rfc2136ZoneService struct {
//	//service *dnsimple.ZonesService
//}
//
//func (z *rfc2136ZoneService) ListZones(accountID string, options *dnsimple.ZoneListOptions) (*dnsimple.ZonesResponse, error) {
//	return z.service.ListZones(accountID, options)
//}
//
//func (z *rfc2136ZoneService) ListRecords(accountID string, zoneID string, options *dnsimple.ZoneRecordListOptions) (*dnsimple.ZoneRecordsResponse, error) {
//	return z.service.ListRecords(accountID, zoneID, options)
//}
//
//func (z *rfc2136ZoneService) CreateRecord(accountID string, zoneID string, recordAttributes dnsimple.ZoneRecord) (*dnsimple.ZoneRecordResponse, error) {
//	return z.service.CreateRecord(accountID, zoneID, recordAttributes)
//}
//
//func (z *rfc2136ZoneService) DeleteRecord(accountID string, zoneID string, recordID int) (*dnsimple.ZoneRecordResponse, error) {
//	return z.service.DeleteRecord(accountID, zoneID, recordID)
//}
//
//func (z *rfc2136ZoneService) UpdateRecord(accountID string, zoneID string, recordID int, recordAttributes dnsimple.ZoneRecord) (*dnsimple.ZoneRecordResponse, error) {
//	return z.service.UpdateRecord(accountID, zoneID, recordID, recordAttributes)
//}

type rfc2136Provider struct {
	//client       dnsimpleZoneServiceInterface
	client *dns.Client
	conf   RFC2136Config
	//identity     identityService
	accountID    string
	domainFilter DomainFilter
	zoneIDFilter ZoneIDFilter
	dryRun       bool
}

type rfc2136Change struct {
	Action string
	//ResourceRecordSet dnsimple.ZoneRecord
}

//const (
//	rfc2136Create = "CREATE"
//	rfc2136Delete = "DELETE"
//	rfc2136Update = "UPDATE"
//)

type RFC2136Config struct {
	DNSServerHost  string
	TSIGSecret     string
	TSIGSecretAlg  string
	TSIGSecretName string
	DryRun         bool
}

// NewRFC2136Provider initializes a new RFC2136 based provider
func NewRFC2136Provider(domainFilter DomainFilter, zoneIDFilter ZoneIDFilter, config RFC2136Config) (Provider, error) {
	if e, ok := tsigAlgs[config.TSIGSecretAlg]; !ok {
		return nil, errors.Errorf("%s is not supported TSIG algorithm", config.TSIGSecretAlg)
	} else {
		config.TSIGSecretAlg = e
	}

	c := new(dns.Client)

	secretName := ensureTrailingDot(config.TSIGSecretName)

	c.TsigSecret = map[string]string{
		secretName: config.TSIGSecret,
	}

	return &rfc2136Provider{
		client:       c,
		conf:         config,
		domainFilter: domainFilter,
		zoneIDFilter: zoneIDFilter,
	}, nil

	//config

	//c := new(dns.Client)
	//oauthToken := os.Getenv("DNSIMPLE_OAUTH")
	//if len(oauthToken) == 0 {
	//	return nil, fmt.Errorf("No dnsimple oauth token provided")
	//}
	//client := dnsimple.NewClient(dnsimple.NewOauthTokenCredentials(oauthToken))
	//provider := &dnsimpleProvider{
	//	client:       dnsimpleZoneService{service: client.Zones},
	//	identity:     identityService{service: client.Identity},
	//	domainFilter: domainFilter,
	//	zoneIDFilter: zoneIDFilter,
	//	dryRun:       dryRun,
	//}
	//whoamiResponse, err := provider.identity.service.Whoami()
	//if err != nil {
	//	return nil, err
	//}
	//provider.accountID = strconv.Itoa(whoamiResponse.Data.Account.ID)
	//return provider, nil
}

//// Returns a list of filtered Zones
//func (p *rfc2136Provider) Zones() (map[string]dnsimple.Zone, error) {
//	//zones := make(map[string]dnsimple.Zone)
//	//page := 1
//	//listOptions := &dnsimple.ZoneListOptions{}
//	//for {
//	//	listOptions.Page = page
//	//	zonesResponse, err := p.client.ListZones(p.accountID, listOptions)
//	//	if err != nil {
//	//		return nil, err
//	//	}
//	//	for _, zone := range zonesResponse.Data {
//	//		if !p.domainFilter.Match(zone.Name) {
//	//			continue
//	//		}
//	//
//	//		if !p.zoneIDFilter.Match(strconv.Itoa(zone.ID)) {
//	//			continue
//	//		}
//	//
//	//		zones[strconv.Itoa(zone.ID)] = zone
//	//	}
//	//
//	//	page++
//	//	if page > zonesResponse.Pagination.TotalPages {
//	//		break
//	//	}
//	//}
//	//return zones, nil
//	return nil, nil
//}

// Records retuns a list of endpoints in a given zone
func (p *rfc2136Provider) Records() (endpoints []*endpoint.Endpoint, _ error) {
	//_, err := p.Zones()
	//if err != nil {
	//	return nil, err
	//}
	m := new(dns.Msg)

	m.SetQuestion("BOOM.localhost.", dns.TypeTXT)

	secretName := ensureTrailingDot(p.conf.TSIGSecretName)

	m.SetTsig(secretName, p.conf.TSIGSecretAlg, tsigFudge, time.Now().Unix())
	//c := new(dns.Client)
	//c.TsigSecret = map[string]string{
	//	secretName: p.conf.TSIGSecret,
	//}

	r, _, err := p.client.Exchange(m, p.conf.DNSServerHost) //c.Exchange(m, "127.0.0.1:53")
	if err != nil {
		return nil, err
	}

	if r != nil && r.Rcode != dns.RcodeSuccess {
		return nil, errors.Errorf("failed to get an valid answer\n%v", r)
	}

	for _, e := range r.Answer {
		fmt.Println(e)
	}

	//p.client.

	//for _, zone := range zones {
	//	page := 1
	//	listOptions := &dnsimple.ZoneRecordListOptions{}
	//	for {
	//		listOptions.Page = page
	//		records, err := p.client.ListRecords(p.accountID, zone.Name, listOptions)
	//		if err != nil {
	//			return nil, err
	//		}
	//		for _, record := range records.Data {
	//			switch record.Type {
	//			case "A", "CNAME", "TXT":
	//				break
	//			default:
	//				continue
	//			}
	//			endpoints = append(endpoints, endpoint.NewEndpointWithTTL(record.Name+"."+record.ZoneID, record.Type, endpoint.TTL(record.TTL), record.Content))
	//		}
	//		page++
	//		if page > records.Pagination.TotalPages {
	//			break
	//		}
	//	}
	//}
	return endpoints, nil
}

//
//// newRFC2136Change initializes a new change to dns records
//func newRFC2136Change(action string, e *endpoint.Endpoint) *dnsimpleChange {
//	ttl := dnsimpleRecordTTL
//	if e.RecordTTL.IsConfigured() {
//		ttl = int(e.RecordTTL)
//	}
//
//	change := &dnsimpleChange{
//		Action: action,
//		ResourceRecordSet: dnsimple.ZoneRecord{
//			Name:    e.DNSName,
//			Type:    e.RecordType,
//			Content: e.Targets[0],
//			TTL:     ttl,
//		},
//	}
//	return change
//}
//
//// newDnsimpleChanges returns a slice of changes based on given action and record
//func newRFC2136Changes(action string, endpoints []*endpoint.Endpoint) []*dnsimpleChange {
//	changes := make([]*dnsimpleChange, 0, len(endpoints))
//	for _, e := range endpoints {
//		changes = append(changes, newDnsimpleChange(action, e))
//	}
//	return changes
//}
//
//// submitChanges takes a zone and a collection of changes and makes all changes from the collection
//func (p *rfc2136Provider) submitChanges(changes []*dnsimpleChange) error {
//	if len(changes) == 0 {
//		log.Infof("All records are already up to date")
//		return nil
//	}
//	zones, err := p.Zones()
//	if err != nil {
//		return err
//	}
//	for _, change := range changes {
//		zone := dnsimpleSuitableZone(change.ResourceRecordSet.Name, zones)
//		if zone == nil {
//			log.Debugf("Skipping record %s because no hosted zone matching record DNS Name was detected ", change.ResourceRecordSet.Name)
//			continue
//		}
//
//		log.Infof("Changing records: %s %v in zone: %s", change.Action, change.ResourceRecordSet, zone.Name)
//
//		change.ResourceRecordSet.Name = strings.TrimSuffix(change.ResourceRecordSet.Name, "."+zone.Name)
//		if !p.dryRun {
//			switch change.Action {
//			case rfc2136Create:
//				//_, err := p.client.CreateRecord(p.accountID, zone.Name, change.ResourceRecordSet)
//				//if err != nil {
//				//	return err
//				//}
//			case rfc2136Delete:
//				_, err := p.GetRecordID(zone.Name, change.ResourceRecordSet.Name)
//				if err != nil {
//					return err
//				}
//				//_, err = p.client.DeleteRecord(p.accountID, zone.Name, recordID)
//				//if err != nil {
//				//	return err
//				//}
//			case rfc2136Update:
//				_, err := p.GetRecordID(zone.Name, change.ResourceRecordSet.Name)
//				if err != nil {
//					return err
//				}
//				//_, err = p.client.UpdateRecord(p.accountID, zone.Name, recordID, change.ResourceRecordSet)
//				//if err != nil {
//				//	return err
//				//}
//			}
//		}
//	}
//	return nil
//}

//// Returns the record ID for a given record name and zone
//func (p *rfc2136Provider) GetRecordID(zone string, recordName string) (recordID int, err error) {
//	//page := 1
//	//listOptions := &dnsimple.ZoneRecordListOptions{Name: recordName}
//	//for {
//	//	listOptions.Page = page
//	//	records, err := p.client.ListRecords(p.accountID, zone, listOptions)
//	//	if err != nil {
//	//		return 0, err
//	//	}
//	//
//	//	for _, record := range records.Data {
//	//		if record.Name == recordName {
//	//			return record.ID, nil
//	//		}
//	//	}
//	//
//	//	page++
//	//	if page > records.Pagination.TotalPages {
//	//		break
//	//	}
//	//}
//	return 0, fmt.Errorf("No record id found")
//}

//
//// dnsimpleSuitableZone returns the most suitable zone for a given hostname and a set of zones.
//func rfc2136SuitableZone(hostname string, zones map[string]dnsimple.Zone) *dnsimple.Zone {
//	var zone *dnsimple.Zone
//	for _, z := range zones {
//		if strings.HasSuffix(hostname, z.Name) {
//			if zone == nil || len(z.Name) > len(zone.Name) {
//				newZ := z
//				zone = &newZ
//			}
//		}
//	}
//	return zone
//}

//// CreateRecords creates records for a given slice of endpoints
//func (p *rfc2136Provider) CreateRecords(endpoints []*endpoint.Endpoint) error {
//	return p.submitChanges(newRFC2136Changes(rfc2136Create, endpoints))
//}
//
//// DeleteRecords deletes records for a given slice of endpoints
//func (p *rfc2136Provider) DeleteRecords(endpoints []*endpoint.Endpoint) error {
//	return p.submitChanges(newRFC2136Changes(rfc2136Delete, endpoints))
//}
//
//// UpdateRecords updates records for a given slice of endpoints
//func (p *rfc2136Provider) UpdateRecords(endpoints []*endpoint.Endpoint) error {
//	return p.submitChanges(newRFC2136Changes(rfc2136Update, endpoints))
//}

// ApplyChanges applies a given set of changes
func (p *rfc2136Provider) ApplyChanges(changes *plan.Changes) error {
	//combinedChanges := make([]*dnsimpleChange, 0, len(changes.Create)+len(changes.UpdateNew)+len(changes.Delete))
	//
	//combinedChanges = append(combinedChanges, newRFC2136Changes(rfc2136Create, changes.Create)...)
	//combinedChanges = append(combinedChanges, newRFC2136Changes(rfc2136Update, changes.UpdateNew)...)
	//combinedChanges = append(combinedChanges, newRFC2136Changes(rfc2136Delete, changes.Delete)...)
	//
	//return p.submitChanges(combinedChanges)
	return nil
}
