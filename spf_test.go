package anotherspf

import (
	"testing"
)

func Test_GmailSPF(t *testing.T) {
	ip := "66.102.1.100"          // Known Google IP
	sender := "kisshan@gmail.com" // Email sender
	domain := "gmail.com"         // Envelope domain

	info, err := Check(ip, domain, sender)
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
	if info.Status != Pass {
		t.Errorf("Expected SPF Pass, got: %v", info.Status)
	}
}

func Test_GmailSPFFailed(t *testing.T) {
	ip := "99.102.1.100"          // Known Google IP
	sender := "kisshan@gmail.com" // Email sender
	domain := "gmail.com"         // Envelope domain

	info, err := Check(ip, domain, sender)
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
	if info.Status != SoftFail {
		t.Errorf("Expected SPF softfail, got: %v", info.Status)
	}
}
