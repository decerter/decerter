// SPDX-License-Identifier: AGPL-3.0-only

package intercept

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/decerter/decerter/internal/filter"
	"github.com/decerter/decerter/internal/tlsrecord"
)

// which directions of a flow a match rule or the hold queue takes
type Directions string

const (
	// what the client sends, towards the server
	UpDirections Directions = "up"
	// what the server sends, towards the client
	DownDirections Directions = "down"
	BothDirections Directions = "both"
)

// how the find and replace values of a match rule are written
type ValueType string

const (
	// the UTF-8 bytes of the text as they are
	TextValueType ValueType = "text"
	// two hex digits per byte, white space between them is ignored
	HexValueType ValueType = "hex"
	// find only: an RE2 expression over the bytes of the message, the replace value is its template ($1, ${name}, $$ for a $)
	RegexValueType ValueType = "regex"
)

// a match-and-replace rule as the API gives it, the values as they were written
// Filter is in the language of --filter, empty is every message; Layer empty is every record layer, http has to be named
type MatchSpec struct {
	Filter      string
	Directions  Directions
	Layer       Layer
	FindType    ValueType
	Find        string
	ReplaceType ValueType
	Replace     string
}

// a declarative rule: every occurrence of find in a message of its directions, layer and filter becomes replace
// a find that spans two messages is not found, a message is one TLS record, one read of a tcp stream or one datagram, or with layer http one whole HTTP/1 message
// ID and Created are given by the rule set, hits counts the messages the rule changed
type MatchRule struct {
	ID      uint64
	Created time.Time
	Spec    MatchSpec
	filter  *filter.Filter
	find    []byte
	pattern *regexp.Regexp
	replace []byte
	hits    *atomic.Uint64
}

// the API rules in their order, the pipeline sees the set as one rule: each rule that matches runs on what the ones before made of the message
// nextID gives every rule an id once, a deleted id is not given again
type RuleSet struct {
	mutex  *sync.RWMutex
	rules  []*MatchRule
	nextID uint64
}

// check and compile a spec, the rule gets its id and time from RuleSet.Add
func NewMatchRule(spec MatchSpec) (rule *MatchRule, err error) {
	rule = &MatchRule{
		ID:      0,
		Created: time.Time{},
		Spec:    spec,
		filter:  nil,
		find:    nil,
		pattern: nil,
		replace: nil,
		hits:    &atomic.Uint64{},
	}

	if rule.Spec.Directions == "" {
		rule.Spec.Directions = BothDirections
	}

	switch rule.Spec.Directions {
	case
		UpDirections,
		DownDirections,
		BothDirections:
	default:
		err = fmt.Errorf("%w: %q, valid values: up, down, both", ErrDirections, spec.Directions)
		return
	}

	switch spec.Layer {
	case
		"",
		TCPLayer,
		TLSLayer,
		UDPLayer,
		DTLSLayer,
		HTTPLayer:
	default:
		err = fmt.Errorf("%w: %q, valid values: tcp, tls, udp, dtls, http", ErrLayer, spec.Layer)
		return
	}

	if spec.Filter != "" {
		parsed, parseErr := filter.Parse(spec.Filter)

		if err = parseErr; err != nil {
			return
		}

		rule.filter = &parsed
	}

	if spec.FindType == "" {
		rule.Spec.FindType = TextValueType
	}

	if spec.ReplaceType == "" {
		rule.Spec.ReplaceType = TextValueType
	}

	if rule.Spec.FindType == RegexValueType {
		pattern, compileErr := regexp.Compile(spec.Find)

		if compileErr != nil {
			err = fmt.Errorf("%w: %w", ErrFind, compileErr)
			return
		}

		// a pattern that matches nothing would insert the replacement between every two bytes
		if pattern.Match(nil) {
			err = fmt.Errorf("%w: the regular expression matches the empty string", ErrFind)
			return
		}

		rule.pattern = pattern
	} else {
		find, decodeErr := DecodeValue(rule.Spec.FindType, spec.Find)

		if decodeErr != nil {
			err = fmt.Errorf("%w: %w", ErrFind, decodeErr)
			return
		}

		if len(find) == 0 {
			err = fmt.Errorf("%w: empty", ErrFind)
			return
		}

		rule.find = find
	}

	replace, decodeErr := DecodeValue(rule.Spec.ReplaceType, spec.Replace)

	if decodeErr != nil {
		err = fmt.Errorf("%w: %w", ErrReplace, decodeErr)
		return
	}

	rule.replace = replace
	return
}

// the bytes of a text or hex value, a regex is no value of its own
func DecodeValue(valueType ValueType, value string) (decoded []byte, err error) {
	switch valueType {
	case TextValueType:
		decoded = []byte(value)
	case HexValueType:
		decoded, err = hex.DecodeString(strings.Join(strings.Fields(value), ""))
	default:
		err = fmt.Errorf("%w: %q, valid values: text, hex", ErrValueType, valueType)
	}

	return
}

func (directions Directions) has(direction tlsrecord.Direction) (isIncluded bool) {
	switch directions {
	case UpDirections:
		isIncluded = direction == tlsrecord.ClientDirection
	case DownDirections:
		isIncluded = direction == tlsrecord.ServerDirection
	case BothDirections:
		isIncluded = true
	}

	return
}

// what a filter of an API rule or of the hold queue sees of a message: the values of its flow, a TLS or DTLS message (and an HTTP one over TLS) is TLS with the fields of its session where the ClientHello was not read
// a message of any other layer has no TLS fields, so no filter of the API waits for a ClientHello that will not come
func FilterValues(message Message) (values filter.Values) {
	values = message.Flow.Values
	session := message.Flow.Session
	isTLS := (message.Layer == TLSLayer) || (message.Layer == DTLSLayer) || ((message.Layer == HTTPLayer) && (session.Version != 0))

	switch {
	case isTLS && (values.TLS != filter.PresentTLSState):
		values = values.WithClientHello(true, session.Version, session.ServerName, session.OfferedProtocols)
	case !isTLS && (values.TLS == filter.UnknownTLSState):
		values.TLS = filter.AbsentTLSState
	default:
	}

	return
}

// a filter that can't be decided does not match
func matchesFilter(scope *filter.Filter, message Message) (isMatch bool) {
	isMatch = (scope == nil) || (scope.Evaluate(FilterValues(message)) == filter.TrueResult)
	return
}

func (rule *MatchRule) Match(message Message) (isMatch bool) {
	isMatch = rule.Spec.Directions.has(message.Direction) && takesLayer(rule.Spec.Layer, message.Layer) && matchesFilter(rule.filter, message)
	return
}

func (rule *MatchRule) Takes(layer Layer) (isTaken bool) {
	isTaken = takesLayer(rule.Spec.Layer, layer)
	return
}

// a message without the find value goes on as it is, a changed one is a new slice
func (rule *MatchRule) Apply(ctx context.Context, message Message) (plain []byte, verdict Verdict, err error) {
	plain = message.Plain
	verdict = ForwardVerdict

	if rule.pattern != nil {
		if !rule.pattern.Match(message.Plain) {
			return
		}

		plain = rule.pattern.ReplaceAll(message.Plain, rule.replace)
	} else {
		if !bytes.Contains(message.Plain, rule.find) {
			return
		}

		plain = bytes.ReplaceAll(message.Plain, rule.find, rule.replace)
	}

	rule.hits.Add(1)
	return
}

// the messages the rule found its value in
func (rule *MatchRule) Hits() (hits uint64) {
	hits = rule.hits.Load()
	return
}

func NewRuleSet() (ruleSet *RuleSet) {
	ruleSet = &RuleSet{
		mutex:  &sync.RWMutex{},
		rules:  nil,
		nextID: 0,
	}
	return
}

// the rule goes last, with the next id
func (ruleSet *RuleSet) Add(rule *MatchRule) {
	ruleSet.mutex.Lock()
	defer ruleSet.mutex.Unlock()
	ruleSet.nextID++
	rule.ID = ruleSet.nextID
	rule.Created = time.Now()
	ruleSet.rules = append(ruleSet.rules, rule)
}

// found is false for an id that is not in the set
func (ruleSet *RuleSet) Delete(id uint64) (rule *MatchRule, found bool) {
	ruleSet.mutex.Lock()
	defer ruleSet.mutex.Unlock()
	index := slices.IndexFunc(ruleSet.rules, func(current *MatchRule) bool {
		return current.ID == id
	})

	if index < 0 {
		return
	}

	rule = ruleSet.rules[index]
	found = true
	ruleSet.rules = slices.Delete(slices.Clone(ruleSet.rules), index, index+1)
	return
}

// the rules in their order; the slice is never changed in place, a change makes a new one
func (ruleSet *RuleSet) List() (rules []*MatchRule) {
	ruleSet.mutex.RLock()
	defer ruleSet.mutex.RUnlock()
	rules = ruleSet.rules
	return
}

func (ruleSet *RuleSet) Takes(layer Layer) (isTaken bool) {
	isTaken = slices.ContainsFunc(ruleSet.List(), func(rule *MatchRule) bool {
		return rule.Takes(layer)
	})
	return
}

func (ruleSet *RuleSet) Match(message Message) (isMatch bool) {
	isMatch = slices.ContainsFunc(ruleSet.List(), func(rule *MatchRule) bool {
		return rule.Match(message)
	})
	return
}

// every rule that matches, in order, each on what the ones before made of the message; a rule deleted meanwhile still finishes this message
func (ruleSet *RuleSet) Apply(ctx context.Context, message Message) (plain []byte, verdict Verdict, err error) {
	current := message

	for _, rule := range ruleSet.List() {
		if !rule.Match(current) {
			continue
		}

		changed, _, applyErr := rule.Apply(ctx, current)

		if err = applyErr; err != nil {
			return
		}

		current.Plain = changed
	}

	plain = current.Plain
	verdict = ForwardVerdict
	return
}
