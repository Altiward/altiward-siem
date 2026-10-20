package main

import (
	"fmt"
	"regexp"
	"strings"
)

// parseYAML reads the subset of YAML the rule files use: block mappings and sequences,
// literal blocks (|), [] and plain or quoted scalars. Scalars stay strings. Anything else
// (flow collections, anchors, folded blocks, trailing comments, tabs) is an error, so a file
// is never read differently here than by Sentinel.
func parseYAML(doc string) (any, error) {
	p := &yamlParser{raw: strings.Split(strings.TrimSuffix(doc, "\n"), "\n")}
	p.skip()
	if p.done() {
		return map[string]any{}, nil
	}
	v, err := p.block(p.indent())
	if err != nil {
		return nil, err
	}
	if !p.done() {
		return nil, p.errorf("unexpected indentation")
	}
	return v, nil
}

type yamlParser struct {
	raw []string
	i   int // the current line
	// item is set while the current line is a sequence item's first key: its text after
	// "- ", at the column it starts in.
	item *struct {
		indent int
		text   string
	}
}

var keyPattern = regexp.MustCompile(`^([A-Za-z0-9_.]+):(?: (.*))?$`)

func (p *yamlParser) done() bool { return p.i >= len(p.raw) }

func (p *yamlParser) errorf(format string, args ...any) error {
	return fmt.Errorf("line %d: %s", p.i+1, fmt.Sprintf(format, args...))
}

// skip moves past blank and comment lines.
func (p *yamlParser) skip() {
	for !p.done() {
		t := strings.TrimLeft(p.raw[p.i], " ")
		if t != "" && !strings.HasPrefix(t, "#") {
			return
		}
		p.i++
	}
}

func (p *yamlParser) indent() int {
	if p.item != nil {
		return p.item.indent
	}
	return len(p.raw[p.i]) - len(strings.TrimLeft(p.raw[p.i], " "))
}

func (p *yamlParser) text() string {
	if p.item != nil {
		return p.item.text
	}
	return strings.TrimLeft(p.raw[p.i], " ")
}

func (p *yamlParser) next() {
	p.item = nil
	p.i++
	p.skip()
}

func isItem(text string) bool { return text == "-" || strings.HasPrefix(text, "- ") }

// block reads the mapping or sequence starting at the current line, at indent.
func (p *yamlParser) block(indent int) (any, error) {
	if strings.Contains(p.raw[p.i], "\t") {
		return nil, p.errorf("tabs aren't allowed")
	}
	if p.item == nil && isItem(p.text()) {
		return p.sequence(indent)
	}
	return p.mapping(indent)
}

func (p *yamlParser) sequence(indent int) (any, error) {
	out := []any{}
	for !p.done() && p.indent() == indent && p.item == nil && isItem(p.text()) {
		if strings.Contains(p.raw[p.i], "\t") {
			return nil, p.errorf("tabs aren't allowed")
		}
		rest := strings.TrimPrefix(strings.TrimPrefix(p.text(), "-"), " ")
		if keyPattern.MatchString(rest) {
			p.item = &struct {
				indent int
				text   string
			}{indent + 2, rest}
			m, err := p.mapping(indent + 2)
			if err != nil {
				return nil, err
			}
			out = append(out, m)
			continue
		}
		if rest == "" {
			return nil, p.errorf("an empty sequence item")
		}
		v, err := p.scalar(rest)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
		p.next()
	}
	if !p.done() && p.indent() > indent {
		return nil, p.errorf("unexpected indentation")
	}
	return out, nil
}

func (p *yamlParser) mapping(indent int) (any, error) {
	out := map[string]any{}
	for !p.done() && p.indent() == indent && (p.item != nil || !isItem(p.text())) {
		if strings.Contains(p.raw[p.i], "\t") {
			return nil, p.errorf("tabs aren't allowed")
		}
		m := keyPattern.FindStringSubmatch(p.text())
		if m == nil {
			return nil, p.errorf("want key: value, got %q", p.text())
		}
		key, rest := m[1], m[2]
		if _, dup := out[key]; dup {
			return nil, p.errorf("%s appears twice", key)
		}
		switch rest {
		case "":
			p.next()
			if p.done() || p.indent() < indent || p.indent() == indent && !isItem(p.text()) {
				return nil, p.errorf("%s has no value", key)
			}
			v, err := p.block(p.indent())
			if err != nil {
				return nil, err
			}
			out[key] = v
		case "|":
			out[key] = p.literal(indent)
		case "[]":
			out[key] = []any{}
			p.next()
		default:
			v, err := p.scalar(rest)
			if err != nil {
				return nil, err
			}
			out[key] = v
			p.next()
		}
	}
	if !p.done() && p.indent() > indent {
		return nil, p.errorf("unexpected indentation")
	}
	return out, nil
}

// literal reads a | block after a key at indent: the lines indented further, with that
// indentation removed and one final newline.
func (p *yamlParser) literal(indent int) string {
	p.item = nil
	p.i++
	var lines []string
	block := -1
	for ; !p.done(); p.i++ {
		line := p.raw[p.i]
		trimmed := strings.TrimLeft(line, " ")
		n := len(line) - len(trimmed)
		if trimmed == "" {
			lines = append(lines, "")
			continue
		}
		if n <= indent {
			break
		}
		if block < 0 {
			block = n
		}
		if n < block {
			break
		}
		lines = append(lines, line[block:])
	}
	for len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	p.skip()
	return strings.Join(lines, "\n") + "\n"
}

func (p *yamlParser) scalar(s string) (string, error) {
	switch {
	case strings.HasPrefix(s, `"`):
		if len(s) < 2 || !strings.HasSuffix(s, `"`) || strings.HasSuffix(s, `\"`) {
			return "", p.errorf("an unclosed quote")
		}
		inner := s[1 : len(s)-1]
		if strings.ContainsAny(strings.ReplaceAll(strings.ReplaceAll(inner, `\\`, ""), `\"`, ""), `"\`) {
			return "", p.errorf("only \\\" and \\\\ escapes are supported")
		}
		return strings.ReplaceAll(strings.ReplaceAll(inner, `\"`, `"`), `\\`, `\`), nil
	case strings.HasPrefix(s, "'"):
		if len(s) < 2 || !strings.HasSuffix(s, "'") {
			return "", p.errorf("an unclosed quote")
		}
		inner := s[1 : len(s)-1]
		if strings.Contains(strings.ReplaceAll(inner, "''", ""), "'") {
			return "", p.errorf("a stray quote")
		}
		return strings.ReplaceAll(inner, "''", "'"), nil
	case strings.ContainsAny(s[:1], "{[&*>|!%@`"):
		return "", p.errorf("%q: flow collections, anchors, tags and folded blocks aren't supported", s)
	case strings.Contains(s, " #"), strings.Contains(s, ": "):
		return "", p.errorf("%q: quote a value holding \" #\" or \": \"", s)
	}
	return s, nil
}
