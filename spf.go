package anotherspf

import (
	"fmt"
)

func Check(ip string, domain string, sender string, resolver DNSResolver) (*SPFInfo, error) {
	info := &SPFInfo{
		LookupCount: 0,
		Lookups:     make(map[string]*Lookup),
		lookedDns:   make(map[string]bool),
		Status:      None,
		resolver:    resolver,
	}

	if resolver == nil {
		info.resolver = &defaultResolver{}
	}

	records, err := info.evalTxt(domain)

	if err != nil {
		info.Status = TempError
		return info, fmt.Errorf("failed to get txt records for domain %s . (Error %v)", domain, err)
	}

	rules, result, err := parse(records)

	if err != nil {
		info.Status = result
		return info, fmt.Errorf("invalid syntax for spf record")
	}

	err = info.evalRules(ip, domain, sender, rules)
	return info, err
}
