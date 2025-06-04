package anotherspf

import "sync"

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
}

type Lookup struct {
	A   bool
	TXT bool
	MX  bool
}

type Rule struct {
	Modifier  Modifier
	Mechanism Mechanism
	Qualifier Qualifier
	Key       string
	Value     string
}

func (le *lookupLimitError) Error() string {
	return le.Message
}
