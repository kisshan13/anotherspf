package anotherspf

import (
	"testing"
)

func Test_SPFRecord(t *testing.T) {
	record := "some random record"

	rules, status, err := parse([]string{record})

	if status != None {
		t.Errorf("Invalid SPF should result in none got %s\n", status)
		return
	}

	if len(rules) > 0 {
		t.Errorf("Invalid SPF should result in len(rules) = 0 got len(rules) = %d\n", len(rules))
	}

	if err == nil {
		t.Errorf("There should be an error if no spf record found spf\n")
	}
}

func Test_InvalidSPFRecord(t *testing.T) {
	record := "v=spf1"

	rules, status, err := parse([]string{record})

	if status != PermError {
		t.Errorf("Invalid SPF should result in permerror got %s\n", status)
		return
	}

	if len(rules) > 0 {
		t.Errorf("Invalid SPF should result in len(rules) = 0 got len(rules) = %d\n", len(rules))
	}

	if err == nil {
		t.Errorf("There should be an error if no spf record found spf\n")
	}
}

func Test_ModeratorSPFRecord(t *testing.T) {
	record := []string{
		"v=spf1 include:_spf.google.com include:mailgun.org -all",
	}

	rules, status, err := parse(record)

	if status != None {
		t.Errorf("On passing record i.e valid records parse() should return none. got %s\n", status)
	}

	if err != nil {
		t.Errorf("On passing record i.e valid records parse() should return nil as error. got %v", err)
	}

	if len(rules) != 3 {
		t.Errorf("For the given record there should be 3 rules in array. got %d", len(rules))
	}

	for i, rule := range rules {

		t.Logf("Rule %d : (Key: %s) (Value: %s)", i+1, rule.Key, rule.Value)

		if i == 0 {
			if rule.Key != "include" {
				t.Errorf("For the given record this item's key value should be include. got %s", rule.Key)
			}

			if rule.Qualifier != QPass {
				t.Errorf("For the given record this item's qualifier should be pass. got %s", rule.Qualifier)
			}

			if rule.Value != "_spf.google.com" {
				t.Errorf("For the given record this item's value should be _spf.google.com. got %s ", rule.Value)
			}

			if rule.ContainsMacro {
				t.Errorf("For the given record this item's should not contain any macro. got macro in value")
			}
		}

		if i == 1 {
			if rule.Key != "include" {
				t.Errorf("For the given record this item's key value should be include. got %s", rule.Key)
			}

			if rule.Qualifier != QPass {
				t.Errorf("For the given record this item's qualifier should be pass. got %s", rule.Qualifier)
			}

			if rule.Value != "mailgun.org" {
				t.Errorf("For the given record this item's value should be an empty string. got %s ", rule.Value)
			}

			if rule.ContainsMacro {
				t.Errorf("For the given record this item's should not contain any macro. got macro in value")
			}
		}

		if i == 2 {
			if rule.Key != "all" {
				t.Errorf("For the given record this item's key value should be all. got %s", rule.Key)
			}

			if rule.Qualifier != QFail {
				t.Errorf("For the given record this item's qualifier should be fail. got %s", rule.Qualifier)
			}

			if rule.Value != "" {
				t.Errorf("For the given record this item's value should be an empty string. got %s ", rule.Value)
			}

			if rule.ContainsMacro {
				t.Errorf("For the given record this item's should not contain any macro. got macro in value")
			}
		}
	}
}

type evaluation struct {
	key           string
	qualifier     Qualifier
	value         string
	containsMacro bool
}

func Test_MacroSPFRecord(t *testing.T) {
	record := []string{
		"v=spf1 ip4:198.51.100.10 a mx exists:%{i}._spf.%{d} include:_spf.example.com -all",
	}

	rules, status, err := parse(record)

	if status != None {
		t.Errorf("On passing record i.e valid records parse() should return none. got %s\n", status)
	}

	if err != nil {
		t.Errorf("On passing record i.e valid records parse() should return nil as error. got %v", err)
	}

	if len(rules) != 6 {
		t.Errorf("For the given record there should be 6 rules in array. got %d", len(rules))
	}

	evaluationResults := map[int]evaluation{
		0: {
			key:           "ip4",
			qualifier:     QPass,
			value:         "198.51.100.10",
			containsMacro: false,
		},
		1: {
			key:           "a",
			qualifier:     QPass,
			value:         "",
			containsMacro: false,
		},
		2: {
			key:           "mx",
			qualifier:     QPass,
			value:         "",
			containsMacro: false,
		},
		3: {
			key:           "exists",
			qualifier:     QPass,
			value:         "%{i}._spf.%{d}",
			containsMacro: true,
		},
		4: {
			key:           "include",
			qualifier:     QPass,
			value:         "_spf.example.com",
			containsMacro: false,
		},
		5: {
			key:           "all",
			qualifier:     QFail,
			value:         "",
			containsMacro: false,
		},
	}

	for i, rule := range rules {

		t.Logf("Rule %d : (Key: %s) (Value: %s)", i+1, rule.Key, rule.Value)

		result, isExists := evaluationResults[i]

		if !isExists {
			t.Errorf("Please check evaluatioResult variable which missing handling case with index %d", i)
		}

		if rule.Key != result.key {
			t.Errorf("For the given record this item's key value should be %s. got %s", result.key, rule.Key)
		}

		if rule.Qualifier != result.qualifier {
			t.Errorf("For the given record this item's qualifier should be %s. got %s", result.qualifier, rule.Qualifier)
		}

		if rule.Value != result.value {
			t.Errorf("For the given record this item's value should be %s. got %s ", result.value, rule.Value)
		}

		if rule.ContainsMacro != result.containsMacro {
			if result.containsMacro {
				t.Errorf("For the given record this item should contain macro. got no such macro in value")
			} else {
				t.Errorf("For the given record this item's should not contain any macro. got macro in value")
			}
		}
	}
}

func Test_MacroSPFWithValues(t *testing.T) {
	context := MacroContext{
		Sender:        "test@example.com",
		IP:            "127.0.0.1",
		Helo:          "example.com",
		Domain:        "example.com",
		Authoritative: "example.com",
	}

	records := []string{
		"v=spf1 ip4:198.51.100.10 a mx exists:%{i}._spf.%{d} include:_spf.example.com -all",
	}

	rules, status, err := parse(records)

	if status != None {
		t.Errorf("On passing record i.e valid records parse() should return none. got %s\n", status)
	}

	if err != nil {
		t.Errorf("On passing record i.e valid records parse() should return nil as error. got %v", err)
	}

	if len(rules) != 6 {
		t.Errorf("For the given record there should be 6 rules in array. got %d", len(rules))
	}

	ruleWithMacro := rules[3]

	if !ruleWithMacro.ContainsMacro {
		t.Errorf("rule at index 3 should contain macro in value, got a non-macro value")
	}

	expanded := expandMacros(ruleWithMacro.Value, context)

	t.Logf("Expanded Value : %s\n", expanded)

	if expanded != "127.0.0.1._spf.example.com" {
		t.Errorf("rule at index 3 with macro should have an expanded value of 127.0.0.1._spf.example.com . got %s", expanded)
	}
}
