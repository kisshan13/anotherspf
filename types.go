package anotherspf

import (
	"net"
	"sync"
)

type Result string
type Modifier string
type Mechanism string
type Qualifier string

type lookupLimitError struct {
	Message string
}

type dnsRecord string

const (
	dnsA   = dnsRecord("a")
	dnsTxt = dnsRecord("txt")
	dnsMx  = dnsRecord("mx")
)

const (
	QPass     = Qualifier("+")
	QFail     = Qualifier("-")
	QSoftFail = Qualifier("~")
	QNeutral  = Qualifier("?")
)

const (
	MAll     = Mechanism("all")
	MInclude = Mechanism("include")
	MA       = Mechanism("a")
	MMx      = Mechanism("mx")
	MPtr     = Mechanism("ptr")
	MIp4     = Mechanism("ip4")
	MIp6     = Mechanism("ip6")
	MExists  = Mechanism("exists")
)

const (
	ModRedirect    = Modifier("redirect")
	ModExplanation = Modifier("exp")
	ModUnknow      = Modifier("unknown-modifier")
)

const (
	Pass      = Result("pass")
	Neutral   = Result("neutral")
	Fail      = Result("fail")
	SoftFail  = Result("softfail")
	TempError = Result("temperror")
	PermError = Result("permerror")
	None      = Result("none")
)

var AllowedDNSLookups = 10

var QualifierResultByStatus = map[Qualifier]Result{
	QFail:     Fail,
	QNeutral:  Neutral,
	QPass:     Pass,
	QSoftFail: SoftFail,
}

type SPFInfo struct {
	LookupCount int
	Lookups     map[string]*Lookup
	lookedDns   map[string]bool
	Status      Result
	PassedRule  *Rule
	Rule        []*Rule
	Record      string
	mu          sync.Mutex
	resolver    DNSResolver
}

type DNSResolver interface {
	LookupTXT(host string) ([]string, error)
	LookupIP(host string) ([]net.IP, error)
	LookupMX(name string) ([]*net.MX, error)
}

type Lookup struct {
	A   bool
	TXT bool
	MX  bool
}

type Rule struct {
	Modifier      Modifier
	Mechanism     Mechanism
	Qualifier     Qualifier
	ContainsMacro bool
	Key           string
	Value         string
}

type MacroContext struct {
	Sender        string // %{s}  Sender’s email address (e.g., "user@example.com")
	IP            string // %{i}  IP address of the sending mail server
	Helo          string // %{h}  HELO/EHLO domain used in SMTP
	Domain        string // %{o}  Sender’s domain (part after @ in email address)
	Authoritative string // %{d}  Authoritative sending domain (SPF record owner)
}

func (le *lookupLimitError) Error() string {
	return le.Message
}
