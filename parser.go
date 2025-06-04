package anotherspf

import (
	"fmt"
	"regexp"
	"strings"
)

var macroRegex = regexp.MustCompile(`%{[slodih]}`)

func containsMacro(s string) bool {
	return macroRegex.MatchString(s)
}

func expandMacros(input string, ctx MacroContext) string {
	return macroRegex.ReplaceAllStringFunc(input, func(m string) string {
		switch m {
		case "%{s}":
			return ctx.Sender
		case "%{l}":
			if i := strings.Index(ctx.Sender, "@"); i != -1 {
				return ctx.Sender[:i]
			}
			return ctx.Sender
		case "%{o}":
			if i := strings.Index(ctx.Sender, "@"); i != -1 {
				return ctx.Sender[i+1:]
			}
			return ctx.Domain
		case "%{d}":
			return ctx.Authoritative
		case "%{i}":
			return ctx.IP
		case "%{h}":
			return ctx.Helo
		default:
			return m
		}
	})
}

func parse(records []string) ([]*Rule, Result, error) {

	record := ""

	for _, r := range records {
		if strings.HasPrefix(r, "v=spf1") {
			record = r
			break
		}
	}

	if record == "" {
		return nil, None, fmt.Errorf("no spf found")
	}

	recordArray := strings.Split(record, " ")

	if len(recordArray) == 1 {
		return nil, PermError, fmt.Errorf("spf syntax error")
	}

	rawRules := recordArray[1:]

	rules := make([]*Rule, 0)

	for _, rule := range rawRules {

		r := &Rule{}

		if strings.HasPrefix(rule, "redirect=") {
			r.Modifier = ModRedirect
			r.Key = "redirect"
			r.Value = rule[len("redirect="):]
			r.ContainsMacro = containsMacro(r.Value)
			rules = append(rules, r)
			continue
		}

		if strings.HasPrefix(rule, "exp=") {
			r.Modifier = ModExplanation
			r.Value = rule[len("exp="):]
			r.Key = "exp"
			r.ContainsMacro = containsMacro(r.Value)
			rules = append(rules, r)
			continue
		}

		if strings.Contains(rule, "=") {
			modifierAndValue := strings.Split(rule, "=")
			if len(modifierAndValue) == 2 {
				r.Modifier = ModUnknow
				r.Key = modifierAndValue[0]
				r.Value = modifierAndValue[1]
				r.ContainsMacro = containsMacro(r.Value)
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
				return nil, PermError, fmt.Errorf("spf syntax error")
			}

			r.Value = value
			r.Key = mech
			r.ContainsMacro = containsMacro(r.Value)
			rules = append(rules, r)

		default:
			return nil, PermError, fmt.Errorf("unknow mechanisms: %s", mech)
		}
	}

	return rules, None, nil
}
