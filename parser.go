package anotherspf

import (
	"fmt"
	"strings"
)

func parse(record string) ([]*Rule, error) {
	recordArray := strings.Split(record, " ")

	if len(recordArray) == 1 {
		return nil, fmt.Errorf("spf syntax error")
	}

	rawRules := recordArray[1:]

	rules := make([]*Rule, 0)

	for _, rule := range rawRules {

		r := &Rule{}

		if strings.HasPrefix(rule, "redirect=") {
			r.Modifier = ModRedirect
			r.Key = "redirect"
			r.Value = rule[len("redirect="):]
			rules = append(rules, r)
			continue
		}

		if strings.HasPrefix(rule, "exp=") {
			r.Modifier = ModExplanation
			r.Value = rule[len("exp="):]
			r.Key = "exp"
			rules = append(rules, r)
			continue
		}

		if strings.Contains(rule, "=") {
			modifierAndValue := strings.Split(rule, "=")
			if len(modifierAndValue) == 2 {
				r.Modifier = ModUnknow
				r.Key = modifierAndValue[0]
				r.Value = modifierAndValue[1]

				rules = append(rules, r)
			}
			continue
		}

		r.Qualifier = QPass

		if len(rule) > 0 {
			switch rule[0] {
			case '+', '-', '~', '?':
				r.Qualifier = Qualifier(rule[0:1])
				rule = rule[1:]
			}
		}

		splittedRule := strings.SplitN(rule, ":", 2)

		mech := splittedRule[0]
		value := ""

		if len(splittedRule) == 2 {
			value = splittedRule[1]
		}

		switch Mechanism(mech) {
		case MAll, MInclude, MA, MMx, MPtr, MIp4, MIp6, MExists:
			r.Mechanism = Mechanism(mech)

			mechanismWithValue := MInclude == r.Mechanism || MIp4 == r.Mechanism || MIp6 == r.Mechanism || MExists == r.Mechanism

			if mechanismWithValue && value == "" {
				return nil, fmt.Errorf("spf syntax error")
			}

			r.Value = value
			r.Key = mech
			rules = append(rules, r)

		default:
			return nil, fmt.Errorf("unknow mechanisms: %s", mech)
		}
	}

	return rules, nil
}
