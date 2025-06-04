package anotherspf

import (
	"fmt"
	"net"
	"strings"
)

func (spf *SPFInfo) checkDnsThreshold(host string, record dnsRecord) (bool, error) {

	spf.mu.Lock()
	defer spf.mu.Unlock()

	if spf.LookupCount >= AllowedDNSLookups {
		return false, &lookupLimitError{
			Message: "maximum depth reached for dns lookup",
		}
	}

	lookup, exists := spf.Lookups[host]

	if !exists {
		lookup = &Lookup{}
		spf.Lookups[host] = lookup
	}

	var alreadyDone bool
	switch record {
	case dnsA:
		alreadyDone = lookup.A
		if !alreadyDone {
			lookup.A = true
		}

	case dnsMx:
		alreadyDone = lookup.MX
		if !alreadyDone {
			lookup.MX = true
		}

	case dnsTxt:
		alreadyDone = lookup.TXT
		if !alreadyDone {
			lookup.TXT = true
		}

	default:
		return false, fmt.Errorf("unsupported record type: %v", record)
	}

	if alreadyDone {
		return false, nil
	}

	spf.LookupCount++
	return true, nil
}

func (spf *SPFInfo) evalTxt(host string) ([]string, error) {
	canEval, err := spf.checkDnsThreshold(host, dnsTxt)

	if err != nil || !canEval {
		return nil, err
	}

	return net.LookupTXT(host)
}

func (spf *SPFInfo) evalA(host string) ([]net.IP, error) {
	canEval, err := spf.checkDnsThreshold(host, dnsA)

	if err != nil || !canEval {
		return nil, err
	}

	return net.LookupIP(host)
}

func (spf *SPFInfo) evalMx(host string) ([]*net.MX, error) {
	canEval, err := spf.checkDnsThreshold(host, dnsMx)

	if err != nil || !canEval {
		return nil, err
	}

	return net.LookupMX(host)
}

func (spf *SPFInfo) evalRules(ip string, host string, rules []*Rule) {

	_, isExists := spf.lookedDns[host]

	if isExists {
		spf.Status = PermError
		return
	}

	spf.mu.Lock()
	spf.lookedDns[host] = true
	spf.mu.Unlock()

	for _, rule := range rules {
		if rule.Mechanism != "" {
			switch rule.Mechanism {
			case MIp4, MIp6:
				result := checkIp(ip, nil, rule)
				spf.Status = result

				if result == Pass {
					spf.PassedRule = rule
					return
				}

			case MMx:
				result, err := spf.evalMx(host)

				if err != nil || result == nil {

					if _, ok := err.(*lookupLimitError); ok {
						spf.Status = PermError
						return
					}

					spf.Status = TempError
					continue
				}

				for _, res := range result {
					hostIps, err := spf.evalA(res.Host)

					if err != nil || result == nil {
						if _, ok := err.(*lookupLimitError); ok {
							spf.Status = PermError
							return
						}

						spf.Status = TempError
					}

					for _, hIp := range hostIps {
						result := checkIp(ip, hIp, nil)
						spf.Status = result
						if result == Pass {
							spf.PassedRule = rule
							return
						}
					}
				}

			case MA:
				result, err := spf.evalA(host)

				if err != nil || result == nil {
					if _, ok := err.(*lookupLimitError); ok {
						spf.Status = PermError
						return
					}

					spf.Status = TempError
					continue
				}

				for _, res := range result {
					result := checkIp(ip, res, nil)
					spf.Status = result
					if result == Pass {
						spf.PassedRule = rule
						return
					}
				}

			case MInclude:
				result, err := spf.evalTxt(rule.Value)

				if err != nil || result == nil {
					if _, ok := err.(*lookupLimitError); ok {
						spf.Status = PermError
						return
					}

					spf.Status = TempError
					continue
				}

				_, res, r, err := evalRecords(result)

				spf.Status = res

				if r == nil || err != nil {
					continue
				}

				spf.evalRules(ip, rule.Value, r)

			case MExists:
				result, err := spf.evalA(rule.Value)

				if err != nil || result == nil {
					spf.Status = Fail
					return
				}

				if len(result) <= 0 {
					spf.Status = Fail
					return
				}

			case MAll:
				spf.Status = QualifierResultByStatus[rule.Qualifier]
				return
			}
		}
	}
}

func checkIp(ip string, anyIp net.IP, rule *Rule) Result {
	senderIp := net.ParseIP(ip)

	if anyIp != nil {
		if ip == anyIp.String() {
			return Pass
		}

		return Fail
	}

	if rule != nil {
		if strings.Contains(rule.Value, "/") {
			_, ipNet, err := net.ParseCIDR(rule.Value)

			if err != nil || ipNet == nil {
				return TempError
			}

			if ipNet.Contains(senderIp) {
				return QualifierResultByStatus[rule.Qualifier]
			}
		}

		if ip == rule.Value {
			return QualifierResultByStatus[rule.Qualifier]
		}

	}
	return None
}

func evalRecords(records []string) (string, Result, []*Rule, error) {
	spfRecord := ""

	for _, record := range records {
		if strings.HasPrefix(record, prefix) {
			spfRecord = record
			break
		}
	}

	if spfRecord == "" {
		return "", TempError, nil, fmt.Errorf("failed to get spf record")
	}

	parsed, err := parse(spfRecord)

	if err != nil {
		return spfRecord, PermError, nil, fmt.Errorf("invalid syntaxt for spf record")
	}

	return spfRecord, Pass, parsed, nil
}

func (spf *spfInfo) parseSpf(records []string) (SPFResult, []*parsedSpf, error) {
	spfRecord := ""

	for _, record := range records {
		if strings.HasPrefix(record, prefix) {
			spfRecord = record
			break
		}
	}

	if spfRecord == "" {
		return TempError, nil, fmt.Errorf("failed to get spf record")
	}

	parsed, err := parse(spfRecord)

	if err != nil {
		return PermError, nil, fmt.Errorf("invalid syntaxt for spf record")
	}

	return Pass, parsed, nil
}

func (spf *spfInfo) compareRules(ip string, host string, parsed []*parsedSpf) (*parsedSpf, SPFResult) {
	passed := &parsedSpf{}
	status := None

	for _, rule := range parsed {
		if rule.mechanism != "" {
			switch rule.mechanism {
			case ip4:
				status = rule.checkIp4(ip)

				if status == Pass {
					passed = rule
					break
				}

			case ip6:
				status = rule.checkIp6(ip)

				if status == Pass {
					passed = rule
					break
				}

			case a:
				spf.mu.Lock()
				val, isExists := spf.lookups[host]

				if !isExists {
					spf.lookups[host] = &lookup{
						a:   true,
						txt: false,
						mx:  false,
					}
				} else {
					if val != nil {

					}
				}
			}
		}
	}

	return passed, status
}

func (spf *spfInfo) evaluateTxtRecords(host string) ([]string, error) {

	spf.mu.Lock()
	defer spf.mu.Unlock()
	spf.lookupDepth += 1

	_, isExists := spf.lookups[host]

	if isExists {
		return nil, nil
	}

	spf.lookups[host] = &lookup{
		txt: true,
		a:   false,
		mx:  false,
	}
	return net.LookupTXT(host)
}

func (rule *parsedSpf) checkA(ip string, host string) SPFResult {
	ips, err := net.LookupIP(host)

	if err != nil {
		return PermError
	}

	for _, i := range ips {
		if i.To4() != nil {
			if ip == i.String() {
				return qualifierStatusMap[rule.qualifier]
			}
		}
	}

	return None
}
