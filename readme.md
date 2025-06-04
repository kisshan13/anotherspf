# `anotherspf`

[![Go Reference](https://pkg.go.dev/badge/github.com/kisshan13/anotherspf.svg)](https://pkg.go.dev/github.com/kisshan13/anotherspf)

`anotherspf` is a lightweight and standards-compliant SPF (Sender Policy Framework) record evaluator written in Go. It performs DNS-based SPF validation for a given IP, sender, and domain, supporting full SPF rule parsing, macro expansion, DNS lookup limits, and recursive evaluation of modifiers like `include` and `redirect`.

## Install

```bash
go get github.com/kisshan13/anotherspf
```

## Features

* [RFC 7208-compliant](https://datatracker.ietf.org/doc/html/rfc7208) SPF evaluation
* Supports IPv4 and IPv6
* Enforces 10-DNS-lookup limit per SPF spec
* Evaluates SPF mechanisms and modifiers:

  * `a`, `mx`, `ip4`, `ip6`, `include`, `exists`, `all`
  * `redirect`, `exp`
* Expands macros like `%{s}`, `%{i}`, `%{h}`, `%{d}` etc.
* Thread-safe and embeddable in other applications

---

## Usage

```go
info, err := anotherspf.Check("192.0.2.1", "example.com", "user@example.com")
if err != nil {
    log.Fatal(err)
}
fmt.Println("SPF result:", info.Status)
```

---

## Core Function

### `func Check(ip string, domain string, sender string) (*SPFInfo, error)`

Evaluates the SPF record for the given sender IP, domain, and envelope sender address.

* Retrieves TXT records
* Parses the SPF string
* Evaluates SPF mechanisms and modifiers recursively
* Returns a structured `SPFInfo` object and evaluation result

---

## Types

### `type SPFInfo`

Tracks state and result of an SPF evaluation.

```go
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
```

### `type Rule`

Represents a parsed SPF rule (mechanism or modifier).

```go
type Rule struct {
    Modifier      Modifier
    Mechanism     Mechanism
    Qualifier     Qualifier
    ContainsMacro bool
    Key           string
    Value         string
}
```

### `type MacroContext`

Carries contextual variables for SPF macro expansion.

```go
type MacroContext struct {
    Sender        string
    IP            string
    Helo          string
    Domain        string
    Authoritative string
}
```

### `type Result`

Possible SPF evaluation results:

```go
const (
    Pass      Result = "pass"
    Fail      Result = "fail"
    SoftFail  Result = "softfail"
    Neutral   Result = "neutral"
    TempError Result = "temperror"
    PermError Result = "permerror"
    None      Result = "none"
)
```

---

## Mechanisms & Modifiers

### Supported SPF Mechanisms:

* `ip4`, `ip6`
* `a`, `mx`, `exists`
* `include`, `all`

## Modifiers:

* `redirect=<domain>`
* `exp=<explanation>`
* Unknown modifiers are parsed but ignored.

## Qualifiers:

```go
const (
    QPass     = "+"
    QFail     = "-"
    QSoftFail = "~"
    QNeutral  = "?"
)
```

---

## 🔐 DNS Lookup Handling

* Enforces a strict **maximum of 10 DNS lookups**
* Deduplicates A, MX, and TXT queries per host
* Fails with `PermError` if the limit is exceeded

---

## 🧪 Internals

### `evalRules(...)`

Recursively evaluates parsed rules with DNS checks.

### `expandMacros(...)`

Expands macros in SPF strings based on context.

### `parse(...)`

Parses SPF TXT records into a structured rule list.

---

## 📄 License

MIT — See the [GitHub repository](https://github.com/kisshan13/anotherspf) for details.

---

