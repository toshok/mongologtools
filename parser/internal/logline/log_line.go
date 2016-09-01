package logline

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"time"
	"unicode"
)

const (
	endRune rune = 1114112
)

func ParseLogLine(input string) (map[string]interface{}, error) {
	p := nonPegLogLineParser{Buffer: input}
	p.Init()
	if err := p.Parse(); err != nil {
		return nil, err
	}
	return p.Fields, nil

}

type nonPegLogLineParser struct {
	Buffer string
	Fields map[string]interface{}

	runes    []rune
	position int
}

func (p *nonPegLogLineParser) Init() {
	p.runes = append([]rune(p.Buffer), endRune)
	p.Fields = make(map[string]interface{})
}

func (p *nonPegLogLineParser) Parse() error {
	var err error
	if err = p.parseTimestamp(); err != nil {
		return err
	}
	if p.lookahead(0) == '[' {
		// we assume version < 3.0
		panic("< 3.0 support not implemented")
	} else {
		// we assume version > 3.0
		if err = p.parseSeverity(); err != nil {
			return err
		}
		if err = p.parseComponent(); err != nil {
			return err
		}
		if err = p.parseContext(); err != nil {
			return err
		}
		if err = p.parseMessage(); err != nil {
			return err
		}
	}

	/*
		if q, ok := p.Fields["query"]; ok {
			if _, ok = p.Fields["query_shape"]; !ok {
				// also calculate the query_shape if we can
				p.Fields["query_shape"] = getQueryShape(q)
			}
		}
	*/

	return nil
}

func (p *nonPegLogLineParser) parseTimestamp() error {
	//fmt.Println("parseTimestamp")
	var readTimestamp string
	var err error

	p.eatWhitespace()

	c := p.lookahead(0)
	if unicode.IsNumber(c) {
		// we assume it's either iso8601-utc or iso8601-local
		if readTimestamp, err = p.readUntil(unicode.Space); err != nil {
			return err
		}
	} else {
		// we assume it's ctime or ctime-no-ms
		var dayOfWeek, month, day, time string

		if dayOfWeek, err = validDayOfWeek(p.readUntil(unicode.Space)); err != nil {
			return err
		}

		p.eatWhitespace()
		if month, err = validMonth(p.readUntil(unicode.Space)); err != nil {
			return err
		}

		p.eatWhitespace()
		if day, err = p.readUntil(unicode.Space); err != nil {
			return err
		}

		p.eatWhitespace()
		if time, err = p.readUntil(unicode.Space); err != nil {
			return err
		}
		readTimestamp = dayOfWeek + " " + month + " " + day + " " + time
	}

	//fmt.Println(" + timestamp = ", readTimestamp)
	p.Fields["timestamp"] = readTimestamp
	return nil
}

func (p *nonPegLogLineParser) parseSeverity() error {
	var err error
	p.eatWhitespace()
	if p.Fields["severity"], err = severityToString(p.advance()); err != nil {
		return err
	}
	if err = p.expectRange(unicode.Space, "expected space after severity"); err != nil {
		return err
	}
	return nil
}

func (p *nonPegLogLineParser) parseComponent() error {
	//fmt.Println("parseComponent")
	p.eatWhitespace()

	var component string
	var err error

	if p.lookahead(0) == '-' {
		component = "-"
		p.advance() // skip the ']'
	} else {
		if component, err = p.readAlphaIdentifier(); err != nil {
			return err
		}
	}
	// XXX(toshok) make sure component is one of:
	// ACCESS, COMMAND, CONTROL, GEO, INDEX, NETWORK, QUERY, REPL, SHARDING, STORAGE, JOURNAL, WRITE, TOTAL, -
	//fmt.Println(" + component = ", component)
	p.Fields["component"] = component
	return nil
}

func (p *nonPegLogLineParser) parseContext() error {
	p.eatWhitespace()

	var err error
	if err = p.expect('['); err != nil {
		return err
	}

	var context string
	if context, err = p.readUntilRune(']'); err != nil {
		return err
	}
	p.advance() // skip the ']'

	//fmt.Println(" + context = ", context)
	p.Fields["context"] = context
	return nil
}

func (p *nonPegLogLineParser) parseMessage() error {
	p.eatWhitespace()

	// check if this message is an operation
	savedPosition := p.position
	operation, err := p.readUntil(unicode.Space)
	if err == nil && p.isOperationName(operation) {
		p.eatWhitespace()

		// yay, an operation.
		p.Fields["operation"] = operation

		var namespace string
		if namespace, err = p.readUntil(unicode.Space); err != nil {
			return err
		}
		p.Fields["namespace"] = namespace

		if err = p.parseOperationBody(); err != nil {
			return err
		}
	} else {
		p.position = savedPosition

		if p.Fields["message"], err = p.readUntilRune(endRune); err != nil {
			return err
		}
	}

	return nil
}

func (p *nonPegLogLineParser) isOperationName(s string) bool {
	return s == "query" || s == "getmore" || s == "insert" || s == "update" || s == "remove" || s == "command"
}

func (p *nonPegLogLineParser) parseOperationBody() error {
	for p.runes[p.position] != endRune {
		var err error
		var done bool

		if done, err = p.parseFieldAndValue(); err != nil {
			return err
		}
		if done {
			// check for a duration
			dur, err := p.readDuration()
			if err != nil {
				return err
			}
			p.Fields["duration"] = dur
			break
		}
	}
	return nil
}

func (p *nonPegLogLineParser) parseFieldAndValue() (bool, error) {
	//fmt.Println("parseFieldAndValue")
	var fieldName string
	var fieldValue interface{}
	var err error

	p.eatWhitespace()

	savedPosition := p.position
	if fieldName, err = p.readUntilRune(':'); err != nil {
		p.position = savedPosition
		return true, nil // swallow the error to give our caller a change to backtrack
	}
	p.position++ // skip the ':'
	p.eatWhitespace()

	// some known fields have a more complicated structure
	if fieldName == "planSummary" {
		if fieldValue, err = p.parsePlanSummary(); err != nil {
			return false, err
		}
	} else if fieldName == "command" {
		// >=2.6 has:  command: <command_name> <command_doc>?
		// <2.6 has:   command: <command_doc>
		firstCharInVal := p.lookahead(0)
		if firstCharInVal != '{' {
			name, err := p.readJSONIdentifier()
			if err != nil {
				return false, err
			}
			p.eatWhitespace()
			p.Fields["command_type"] = name
		}

		if fieldValue, err = p.parseJSONMap(); err != nil {
			return false, err
		}
	} else {
		firstCharInVal := p.lookahead(0)
		switch {
		case firstCharInVal == '{':
			if fieldValue, err = p.parseJSONMap(); err != nil {
				return false, err
			}
			//fmt.Printf("buh? '%s'\n", string([]rune{firstCharInVal}))
		case unicode.IsDigit(firstCharInVal):
			if fieldValue, err = p.readNumber(); err != nil {
				return false, err
			}
		case firstCharInVal == '"':
			if fieldValue, err = p.parseStringValue(firstCharInVal); err != nil {
				return false, err
			}
		default:
			return false, errors.New(fmt.Sprintf("unexpected start character for value of field '%s'", fieldName))
		}
	}

	p.Fields[fieldName] = fieldValue
	//fmt.Println("done parsing field ", fieldName)
	return false, nil
}

func (p *nonPegLogLineParser) parsePlanSummary() (interface{}, error) {
	var rv []interface{}

	p.eatWhitespace()

	for {
		elem, err := p.parsePlanSummaryElement()
		if err != nil {
			return nil, err
		}
		if elem != nil {
			rv = append(rv, elem)
		}
		p.eatWhitespace()

		if p.lookahead(0) != ',' {
			break
		} else {
			p.position++
		}
	}

	return rv, nil
}

func (p *nonPegLogLineParser) parsePlanSummaryElement() (interface{}, error) {
	rv := make(map[string]interface{})

	p.eatWhitespace()

	savedPosition := p.position

	var stage string
	var err error

	if stage, err = p.readUpcaseIdentifier(); err != nil {
		p.position = savedPosition
		return nil, nil
	}

	p.eatWhitespace()
	c := p.lookahead(0)
	if c == '{' {
		if rv[stage], err = p.parseJSONMap(); err != nil {
			return nil, nil
		}
	} else {
		rv[stage] = true
	}

	return rv, nil
}

func (p *nonPegLogLineParser) readNumber() (float64, error) {
	startPosition := p.position
	endPosition := startPosition
	numberChecks := []interface{}{unicode.Digit, '.', '+', '-', 'e', 'E'}
	for check(p.runes[endPosition], numberChecks) {
		endPosition++
	}

	if p.runes[endPosition] == endRune {
		return 0, errors.New("found end of line before expected unicode range")
	}

	p.position = endPosition

	rv, err := strconv.ParseFloat(string(p.runes[startPosition:endPosition]), 64)
	if err == nil {
		//fmt.Println(" + NUMBER VALUE =", rv)
	}

	return rv, err
}

func (p *nonPegLogLineParser) readDuration() (float64, error) {
	startPosition := p.position
	endPosition := startPosition

	for unicode.IsDigit(p.runes[endPosition]) {
		endPosition++
	}

	if p.runes[endPosition] != 'm' || p.runes[endPosition+1] != 's' {
		return 0, errors.New("invalid duration specifier")
	}

	rv, err := strconv.ParseFloat(string(p.runes[startPosition:endPosition]), 64)
	p.position = endPosition + 2
	if err == nil {
		//fmt.Println(" + DURATION =", rv)
	}

	return rv, err
}

func (p *nonPegLogLineParser) parseJSONMap() (interface{}, error) {
	// we assume we're on the '{'
	p.position++

	rv := make(map[string]interface{})

	for {
		var key string
		var value interface{}
		var err error

		p.eatWhitespace()
		// we support keys both of the form: { foo: ... } and { "foo": ... }
		fc := p.lookahead(0)
		if fc == '"' || fc == '\'' {
			if key, err = p.parseStringValue(fc); err != nil {
				return nil, err
			}
		} else {
			if key, err = p.readJSONIdentifier(); err != nil {
				return nil, err
			}
		}

		//fmt.Println("json key = ", key)

		if key != "" {
			p.eatWhitespace()
			if err = p.expect(':'); err != nil {
				return nil, err
			}
			p.eatWhitespace()

			if value, err = p.parseJSONValue(); err != nil {
				return nil, err
			}
			rv[key] = value
		}

		p.eatWhitespace()
		commaOrRbrace := p.lookahead(0)
		//fmt.Printf("commaOrRbrace = '%s'\n", string([]rune{commaOrRbrace}))
		if commaOrRbrace == '}' {
			p.position++
			break
		} else if commaOrRbrace == ',' {
			p.position++
		} else {
			return nil, errors.New("expected '}' or ',' in json")
		}

	}

	return rv, nil
}

func (p *nonPegLogLineParser) parseJSONArray() (interface{}, error) {
	var rv []interface{}

	// we assume we're on the '['
	p.position++

	p.eatWhitespace()
	if p.lookahead(0) == ']' {
		p.position++
		return rv, nil
	}

	for {
		var value interface{}
		var err error

		if value, err = p.parseJSONValue(); err != nil {
			return nil, err
		}

		rv = append(rv, value)

		p.eatWhitespace()
		commaOrRbrace := p.lookahead(0)
		//fmt.Printf("commaOrRbrace = '%s'\n", string([]rune{commaOrRbrace}))
		if commaOrRbrace == ']' {
			p.position++
			break
		} else if commaOrRbrace == ',' {
			p.position++
		} else {
			return nil, errors.New("expected ']' or ',' in json")
		}
		p.eatWhitespace()
	}

	return rv, nil
}

func (p *nonPegLogLineParser) parseJSONValue() (interface{}, error) {
	var value interface{}
	var err error

	firstCharInVal := p.lookahead(0)
	switch {
	case firstCharInVal == '{':
		if value, err = p.parseJSONMap(); err != nil {
			return nil, err
		}
	case firstCharInVal == '[':
		if value, err = p.parseJSONArray(); err != nil {
			return nil, err
		}
	case check(firstCharInVal, []interface{}{unicode.Digit, '-', '+', '.'}):
		if value, err = p.readNumber(); err != nil {
			return nil, err
		}
	case firstCharInVal == '"':
		if p.lookahead(1) != '{' {
			if value, err = p.parseStringValue(firstCharInVal); err != nil {
				return nil, err
			}
		} else {
			// ugh.  mongodb seems to put partial misquoted json blobs in as strings.  e.g. something like:
			//   payload: "{"alert":"something went wrong","id":"12345","type":"...",<space>
			// so we do an equally terrible thing and notice the "{... prefix, ignore the leading ", and
			// keep track of quote nested, reading until we hit ,<space> in an unquoted context.

			p.position++
			endPosition := p.position
			quoted := false
			for {
				if !quoted && p.matchAhead(endPosition, "\", ") {
					endPosition = endPosition + 1 // we want to end on the ','
					break
				} else if quoted && p.matchAhead(endPosition, "...\", ") {
					endPosition = endPosition + 4 // we want to end on the ','
					break
				} else if p.runes[endPosition] == '"' {
					quoted = !quoted
				}

				endPosition++
				if p.runes[endPosition] == endRune {
					return nil, errors.New("unexpected end of line reading json value")
				}
			}
			value = string(p.runes[p.position:endPosition])
			//fmt.Println("hey boys, we read ", value)
			p.position = endPosition
		}
	case unicode.IsLetter(firstCharInVal):
		if value, err = p.readJSONIdentifier(); err != nil {
			return nil, err
		}
		if value == "null" {
			value = nil
		} else if value == "true" {
			value = true
		} else if value == "false" {
			value = false
		} else if value == "new" {
			p.eatWhitespace()
			if value, err = p.readJSONIdentifier(); err != nil {
				return nil, err
			}
			if value != "Date" {
				return nil, errors.New(fmt.Sprintf("unexpected constructor: %s", value))
			}
			// we expect "new Date(123456789)"
			if err = p.expect('('); err != nil {
				return nil, err
			}
			var dateNum float64
			if dateNum, err = p.readNumber(); err != nil {
				return nil, err
			}
			if err = p.expect(')'); err != nil {
				return nil, err
			}

			if math.Floor(dateNum) != dateNum {
				return nil, errors.New(fmt.Sprintf("expected int in `new Date()`"))
			}
			unixSec := int64(dateNum) / 1000
			unixNS := int64(dateNum) % 1000 * 1000000
			value = time.Unix(unixSec, unixNS)
			//fmt.Println(" + DATE ", value)
		} else if value == "Timestamp" {
			var ts string
			if p.lookahead(0) == '(' {
				//fmt.Println("timestamp(")
				if ts, err = p.readUntilRune(')'); err != nil {
					return nil, err
				}
			} else {
				//fmt.Println("timestamp<space>")
				p.eatWhitespace()
				if ts, err = p.readWhile([]interface{}{unicode.Digit, '|'}); err != nil {
					return nil, err
				}
			}
			//fmt.Println("timestamp = ", ts)
			value = ts
			// XXX(toshok) more here
		} else if value == "ObjectId" {
			if err = p.expect('('); err != nil {
				return nil, err
			}
			quote := p.lookahead(0) // keep ahold of the quote so we can match it
			if p.lookahead(0) != '\'' && p.lookahead(0) != '"' {
				return nil, errors.New("expected ' or \" in ObjectId")
			}
			p.position++

			hexRunes := []interface{}{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'a', 'b', 'c', 'd', 'e', 'f'}
			var hex string
			if hex, err = p.readWhile(hexRunes); err != nil {
				return nil, err
			}
			if err = p.expect(quote); err != nil {
				return nil, err
			}
			if err = p.expect(')'); err != nil {
				return nil, err
			}
			value = hex
			// XXX(toshok) more here
		} else {
			return nil, errors.New(fmt.Sprintf("unexpected start of JSON value: %s", value))
		}
	default:
		return nil, errors.New(fmt.Sprintf("unexpected start character for JSON value of field: %s", string([]rune{firstCharInVal})))
	}

	return value, nil
}

func (p *nonPegLogLineParser) parseStringValue(quote rune) (string, error) {
	var s string
	var err error

	p.position++ // skip starting quote
	if s, err = p.readUntilRune(quote); err != nil {
		return "", err
	}
	p.position++ // skip ending quote

	//fmt.Println("+ STRING VALUE: ", s)

	return s, nil
}

func (p *nonPegLogLineParser) readJSONIdentifier() (string, error) {
	startPosition := p.position
	endPosition := startPosition

	for check(p.runes[endPosition], []interface{}{unicode.Letter, unicode.Digit, '$', '_', '.', '*'}) {
		endPosition++
	}

	p.position = endPosition
	return string(p.runes[startPosition:endPosition]), nil
}

func (p *nonPegLogLineParser) readUpcaseIdentifier() (string, error) {
	startPosition := p.position
	endPosition := startPosition
	for !unicode.IsSpace(p.runes[endPosition]) && p.runes[endPosition] != endRune {
		if p.runes[endPosition] != '_' && !unicode.IsDigit(p.runes[endPosition]) && (!unicode.IsLetter(p.runes[endPosition]) || !unicode.IsUpper(p.runes[endPosition])) {
			return "", errors.New(fmt.Sprintf("rune '%s' is illegal in this context", string([]rune{p.runes[endPosition]})))
		}
		endPosition++
	}

	p.position = endPosition
	return string(p.runes[startPosition:endPosition]), nil
}

func (p *nonPegLogLineParser) readAlphaIdentifier() (string, error) {
	startPosition := p.position
	endPosition := startPosition
	for !unicode.IsSpace(p.runes[endPosition]) && p.runes[endPosition] != endRune {
		if !unicode.IsLetter(p.runes[endPosition]) {
			return "", errors.New(fmt.Sprintf("rune '%s' is illegal in this context", string([]rune{p.runes[endPosition]})))
		}
		endPosition++
	}

	p.position = endPosition
	return string(p.runes[startPosition:endPosition]), nil
}

func (p *nonPegLogLineParser) readUntil(untilRangeTable *unicode.RangeTable) (string, error) {
	startPosition := p.position
	endPosition := startPosition
	for p.runes[endPosition] != endRune && !unicode.Is(untilRangeTable, p.runes[endPosition]) {
		endPosition++
	}

	if p.runes[endPosition] == endRune {
		return "", errors.New("found end of line before expected unicode range")
	}

	p.position = endPosition

	return string(p.runes[startPosition:endPosition]), nil
}

func (p *nonPegLogLineParser) readUntilRune(untilRune rune) (string, error) {
	startPosition := p.position
	endPosition := startPosition
	for p.runes[endPosition] != untilRune && p.runes[endPosition] != endRune {
		endPosition++
	}

	if p.runes[endPosition] == endRune && untilRune != endRune {
		return "", errors.New(fmt.Sprintf("found end of line before expected rune '%s'", string([]rune{untilRune})))
	}

	p.position = endPosition

	return string(p.runes[startPosition:endPosition]), nil
}

func (p *nonPegLogLineParser) readWhile(checks []interface{}) (string, error) {
	startPosition := p.position
	endPosition := startPosition

	for p.runes[endPosition] != endRune {
		if !check(p.runes[endPosition], checks) {
			break
		}
		endPosition++
	}

	if p.runes[endPosition] == endRune {
		return "", errors.New("unexpected end of line")
	}

	p.position = endPosition

	return string(p.runes[startPosition:endPosition]), nil
}

func (p *nonPegLogLineParser) lookahead(amount int) rune {
	return p.runes[p.position+amount]
}

func (p *nonPegLogLineParser) matchAhead(startIdx int, s string) bool {
	runes := []rune(s)
	for i, r := range runes {
		if r != p.runes[startIdx+i] {
			return false
		}
	}
	return true
}

func (p *nonPegLogLineParser) advance() rune {
	r := p.runes[p.position]
	p.position++
	return r
}

func (p *nonPegLogLineParser) expect(past rune) error {
	r := p.advance()
	if r != past {
		return errors.New(fmt.Sprintf("expected '%s', but got '%s'", string([]rune{past}), string([]rune{r})))
	}
	return nil
}

func (p *nonPegLogLineParser) expectRange(rt *unicode.RangeTable, errStr string) error {
	if !unicode.Is(rt, p.advance()) {
		return errors.New(errStr)
	}
	return nil
}

func (p *nonPegLogLineParser) eatWhitespace() {
	for unicode.Is(unicode.Space, p.runes[p.position]) {
		p.position++
	}
}

func severityToString(sev rune) (string, error) {
	switch sev {
	case 'D':
		return "debug", nil
	case 'I':
		return "informational", nil
	case 'W':
		return "warning", nil
	case 'E':
		return "error", nil
	case 'F':
		return "fatal", nil
	default:
		return "", errors.New(fmt.Sprintf("unknown severity '%s'", string([]rune{sev})))
	}
}

func check(r rune, checks []interface{}) bool {
	for _, c := range checks {
		if doCheck(r, c) {
			return true
		}
	}
	return false
}

func doCheck(r rune, c interface{}) bool {
	if rt, ok := c.(*unicode.RangeTable); ok {
		if unicode.Is(rt, r) {
			return true
		}
	} else if runeCheck, ok := c.(rune); ok {
		if r == runeCheck {
			return true
		}
	} else {
		panic("unhandled check in doCheck")
	}
	return false
}
func validDayOfWeek(dayOfWeek string, err error) (string, error) {
	if len(dayOfWeek) != 3 {
		return "", errors.New("invalid day of week")
	}
	// XXX(toshok) validate against a list
	return dayOfWeek, nil
}

func validMonth(month string, err error) (string, error) {
	if len(month) != 3 {
		return "", errors.New("invalid month")
	}
	// XXX(toshok) validate against a list
	return month, nil
}
