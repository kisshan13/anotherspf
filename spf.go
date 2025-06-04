package anotherspf

import (
	"fmt"
	"sync"
)

var prefix = "v=spf1"
var lookupLimit = 10

type spfInfo struct {
	lookupDepth int
	lookups     map[string]*lookup
	mu          sync.Mutex
}

type lookup struct {
	a   bool
	txt bool
	mx  bool
}

func Check(ip string, domain string, sender string) (SPFInfo, error) {
	info := &SPFInfo{
		LookupDepth: 0,
		Lookups:     make(map[string]*Lookup),
		Status:      None,
	}
	
	records, err := info.evaluateTxtRecords(domain)

	if err != nil {
		return TempError, fmt.Errorf("failed to get txt records for domain %s . (Error %v)", domain, err)
	}

	result, parsed, err := info.parseSpf(records)

	if parsed == nil || err != nil {
		return result, err
	}

	if err != nil {
		return PermError, fmt.Errorf("invalid syntax for spf record")
	}

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
			}
		}
	}

	return Neutral, nil
}
