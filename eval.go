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

func (spf *SPFInfo) evalRules(ip string, host string, sender string, rules []*Rule) error {

	context := MacroContext{
		Sender:        sender,
		IP:            ip,
		Helo:          host,
		Domain:        host,
		Authoritative: host,
	}

	_, isExists := spf.lookedDns[host]

	if isExists {
		spf.Status = PermError
		return nil
	}

	spf.mu.Lock()
	spf.lookedDns[host] = true
	spf.mu.Unlock()

	for _, rule := range rules {
		if rule.Key != "" {
			if rule.ContainsMacro {
				rule.Value = expandMacros(rule.Value, context)
			}

			switch rule.Key {
			case string(MIp4), string(MIp6):
				result := checkIp(ip, nil, rule)
				spf.Status = result

				if result == Pass {
					spf.PassedRule = rule
					return nil
				}

			case string(MMx):
				result, err := spf.evalMx(host)

				if err != nil || result == nil {

					if _, ok := err.(*lookupLimitError); ok {
						spf.Status = PermError
						return nil
					}

					spf.Status = TempError
					continue
				}

				for _, res := range result {
					hostIps, err := spf.evalA(res.Host)

					if err != nil || result == nil {
						if _, ok := err.(*lookupLimitError); ok {
							spf.Status = PermError
							return nil
						}

						spf.Status = TempError
					}

					for _, hIp := range hostIps {
						result := checkIp(ip, hIp, nil)
						spf.Status = result
						if result == Pass {
							spf.PassedRule = rule
							return nil
						}
					}
				}

			case string(MA):
				result, err := spf.evalA(host)

				if err != nil || result == nil {
					if _, ok := err.(*lookupLimitError); ok {
						spf.Status = PermError
						return nil
					}

					spf.Status = TempError
					continue
				}

				for _, res := range result {
					result := checkIp(ip, res, nil)
					spf.Status = result
					if result == Pass {
						spf.PassedRule = rule
						return nil
					}
				}

			case string(MInclude):
				result, err := spf.evalTxt(rule.Value)

				if err != nil || result == nil {
					if _, ok := err.(*lookupLimitError); ok {
						spf.Status = PermError
						return nil
					}

					spf.Status = TempError
					continue
				}

				r, res, err := parse(result)

				if err != nil {
					spf.Status = res
					return err
				}

				if len(r) == 0 {
					spf.Status = PermError
					return err
				}

				spf.evalRules(ip, rule.Value, sender, r)

				if spf.Status == Pass {
					return nil
				}

			case string(MExists):
				result, err := spf.evalA(rule.Value)

				if err != nil || result == nil {
					if _, ok := err.(*lookupLimitError); ok {
						spf.Status = PermError
						return nil
					}

					spf.Status = Fail
					return nil
				}

				if len(result) <= 0 {
					spf.Status = Fail
					return nil
				}

			case string(ModRedirect):
				if rule.Value == "" {
					spf.Status = PermError
					return nil
				}

				result, err := spf.evalTxt(rule.Value)

				if err != nil || result == nil {
					if _, ok := err.(*lookupLimitError); ok {
						spf.Status = PermError
						return nil
					}

					spf.Status = Fail
					return nil
				}

				r, res, err := parse(result)

				if err != nil {
					spf.Status = res
					return nil
				}

				if len(r) == 0 {
					spf.Status = PermError
					return nil
				}

				spf.evalRules(ip, rule.Value, sender, r)

			case string(MAll):
				spf.Status = QualifierResultByStatus[rule.Qualifier]
				return nil
			}
		}

	}

	return nil
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
