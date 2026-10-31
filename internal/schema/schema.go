// Package schema implements the small JSON Schema subset that operation
// parameters and state tool arguments are checked against.
//
// Supported keywords: type (object, string, integer, boolean, array),
// properties, required, additionalProperties (false only), pattern, enum,
// minLength, maxLength, minimum, maximum, items, plus the annotations
// description and title. Any other keyword fails at compile time, so a
// definition can never rely on a check this validator silently skips.
package schema

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"unicode/utf8"
)

// Schema is a compiled schema node.
type Schema struct {
	Type       string
	Properties map[string]*Schema
	Required   []string
	// ClosedObject is true when additionalProperties is false.
	ClosedObject bool
	Pattern      *regexp.Regexp
	Enum         []any
	MinLength    *int
	MaxLength    *int
	Minimum      *float64
	Maximum      *float64
	Items        *Schema
	Description  string
}

var allowedKeywords = map[string]bool{
	"type": true, "properties": true, "required": true, "additionalProperties": true,
	"pattern": true, "enum": true, "minLength": true, "maxLength": true,
	"minimum": true, "maximum": true, "items": true, "description": true, "title": true,
}

var allowedTypes = map[string]bool{"object": true, "string": true, "integer": true, "boolean": true, "array": true}

// Compile parses and checks a schema document.
func Compile(doc []byte) (*Schema, error) {
	var raw any
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("schema: %w", err)
	}
	return compileNode(raw, "#")
}

func compileNode(raw any, path string) (*Schema, error) {
	obj, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("schema %s: must be an object", path)
	}
	for k := range obj {
		if !allowedKeywords[k] {
			return nil, fmt.Errorf("schema %s: unsupported keyword %q", path, k)
		}
	}
	s := &Schema{}
	t, ok := obj["type"].(string)
	if !ok || !allowedTypes[t] {
		return nil, fmt.Errorf("schema %s: type must be one of object, string, integer, boolean, array", path)
	}
	s.Type = t
	if d, ok := obj["description"]; ok {
		ds, ok := d.(string)
		if !ok {
			return nil, fmt.Errorf("schema %s: description must be a string", path)
		}
		s.Description = ds
	}
	if ti, ok := obj["title"]; ok {
		if _, ok := ti.(string); !ok {
			return nil, fmt.Errorf("schema %s: title must be a string", path)
		}
	}

	only := func(kw string, types ...string) error {
		if _, present := obj[kw]; !present {
			return nil
		}
		for _, ty := range types {
			if ty == t {
				return nil
			}
		}
		return fmt.Errorf("schema %s: %s does not apply to type %s", path, kw, t)
	}
	for kw, types := range map[string][]string{
		"properties": {"object"}, "required": {"object"}, "additionalProperties": {"object"},
		"pattern": {"string"}, "minLength": {"string"}, "maxLength": {"string"},
		"minimum": {"integer"}, "maximum": {"integer"}, "items": {"array"},
		"enum": {"string", "integer"},
	} {
		if err := only(kw, types...); err != nil {
			return nil, err
		}
	}

	if p, ok := obj["properties"]; ok {
		pm, ok := p.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("schema %s: properties must be an object", path)
		}
		s.Properties = map[string]*Schema{}
		for name, sub := range pm {
			cs, err := compileNode(sub, path+"/properties/"+name)
			if err != nil {
				return nil, err
			}
			s.Properties[name] = cs
		}
	}
	if r, ok := obj["required"]; ok {
		rl, ok := r.([]any)
		if !ok {
			return nil, fmt.Errorf("schema %s: required must be an array", path)
		}
		for _, item := range rl {
			name, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("schema %s: required entries must be strings", path)
			}
			if _, declared := s.Properties[name]; !declared {
				return nil, fmt.Errorf("schema %s: required property %q is not declared", path, name)
			}
			s.Required = append(s.Required, name)
		}
	}
	if ap, ok := obj["additionalProperties"]; ok {
		b, ok := ap.(bool)
		if !ok || b {
			return nil, fmt.Errorf("schema %s: additionalProperties must be false", path)
		}
		s.ClosedObject = true
	}
	if p, ok := obj["pattern"]; ok {
		ps, ok := p.(string)
		if !ok {
			return nil, fmt.Errorf("schema %s: pattern must be a string", path)
		}
		re, err := regexp.Compile(ps)
		if err != nil {
			return nil, fmt.Errorf("schema %s: pattern: %w", path, err)
		}
		s.Pattern = re
	}
	var err error
	if s.MinLength, err = intKeyword(obj, "minLength", path); err != nil {
		return nil, err
	}
	if s.MaxLength, err = intKeyword(obj, "maxLength", path); err != nil {
		return nil, err
	}
	if s.Minimum, err = numKeyword(obj, "minimum", path); err != nil {
		return nil, err
	}
	if s.Maximum, err = numKeyword(obj, "maximum", path); err != nil {
		return nil, err
	}
	if e, ok := obj["enum"]; ok {
		el, ok := e.([]any)
		if !ok || len(el) == 0 {
			return nil, fmt.Errorf("schema %s: enum must be a non-empty array", path)
		}
		for _, v := range el {
			if err := checkType(t, v); err != nil {
				return nil, fmt.Errorf("schema %s: enum value: %w", path, err)
			}
		}
		s.Enum = el
	}
	if it, ok := obj["items"]; ok {
		cs, err := compileNode(it, path+"/items")
		if err != nil {
			return nil, err
		}
		s.Items = cs
	}
	return s, nil
}

func intKeyword(obj map[string]any, kw, path string) (*int, error) {
	v, ok := obj[kw]
	if !ok {
		return nil, nil
	}
	n, ok := v.(json.Number)
	if !ok {
		return nil, fmt.Errorf("schema %s: %s must be a non-negative integer", path, kw)
	}
	i, err := strconv.Atoi(n.String())
	if err != nil || i < 0 {
		return nil, fmt.Errorf("schema %s: %s must be a non-negative integer", path, kw)
	}
	return &i, nil
}

func numKeyword(obj map[string]any, kw, path string) (*float64, error) {
	v, ok := obj[kw]
	if !ok {
		return nil, nil
	}
	n, ok := v.(json.Number)
	if !ok {
		return nil, fmt.Errorf("schema %s: %s must be a number", path, kw)
	}
	f, err := n.Float64()
	if err != nil {
		return nil, fmt.Errorf("schema %s: %s must be a number", path, kw)
	}
	return &f, nil
}

// Validate checks a decoded JSON value (from encoding/json, with or without
// UseNumber) against the schema.
func (s *Schema) Validate(v any) error {
	return s.validate(v, "")
}

func (s *Schema) validate(v any, path string) error {
	at := func(format string, args ...any) error {
		p := path
		if p == "" {
			p = "value"
		}
		return fmt.Errorf("%s: %s", p, fmt.Sprintf(format, args...))
	}
	if err := checkType(s.Type, v); err != nil {
		return at("%v", err)
	}
	switch s.Type {
	case "object":
		obj := v.(map[string]any)
		for _, name := range s.Required {
			if _, ok := obj[name]; !ok {
				return at("missing required property %q", name)
			}
		}
		names := make([]string, 0, len(obj))
		for name := range obj {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			sub, declared := s.Properties[name]
			if !declared {
				if s.ClosedObject {
					return at("unexpected property %q", name)
				}
				continue
			}
			if err := sub.validate(obj[name], join(path, name)); err != nil {
				return err
			}
		}
	case "string":
		str := v.(string)
		n := utf8.RuneCountInString(str)
		if s.MinLength != nil && n < *s.MinLength {
			return at("shorter than %d characters", *s.MinLength)
		}
		if s.MaxLength != nil && n > *s.MaxLength {
			return at("longer than %d characters", *s.MaxLength)
		}
		if s.Pattern != nil && !s.Pattern.MatchString(str) {
			return at("does not match pattern %s", s.Pattern.String())
		}
	case "integer":
		f, _ := toFloat(v)
		if s.Minimum != nil && f < *s.Minimum {
			return at("less than minimum %v", *s.Minimum)
		}
		if s.Maximum != nil && f > *s.Maximum {
			return at("greater than maximum %v", *s.Maximum)
		}
	case "array":
		if s.Items != nil {
			for i, item := range v.([]any) {
				if err := s.Items.validate(item, fmt.Sprintf("%s[%d]", path, i)); err != nil {
					return err
				}
			}
		}
	}
	if s.Enum != nil {
		found := false
		for _, e := range s.Enum {
			if equal(e, v) {
				found = true
				break
			}
		}
		if !found {
			return at("not one of the allowed values")
		}
	}
	return nil
}

func join(path, name string) string {
	if path == "" {
		return name
	}
	return path + "." + name
}

func checkType(t string, v any) error {
	switch t {
	case "object":
		if _, ok := v.(map[string]any); ok {
			return nil
		}
	case "string":
		if _, ok := v.(string); ok {
			return nil
		}
	case "boolean":
		if _, ok := v.(bool); ok {
			return nil
		}
	case "array":
		if _, ok := v.([]any); ok {
			return nil
		}
	case "integer":
		if isInteger(v) {
			return nil
		}
	}
	return fmt.Errorf("must be of type %s", t)
}

func isInteger(v any) bool {
	switch n := v.(type) {
	case json.Number:
		_, err := strconv.ParseInt(n.String(), 10, 64)
		return err == nil
	case float64:
		return n == math.Trunc(n) && !math.IsInf(n, 0) && math.Abs(n) < 1<<53
	case int:
		return true
	case int64:
		return true
	}
	return false
}

func toFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	}
	return 0, false
}

func equal(a, b any) bool {
	if as, ok := a.(string); ok {
		bs, ok := b.(string)
		return ok && as == bs
	}
	af, aok := toFloat(a)
	bf, bok := toFloat(b)
	return aok && bok && af == bf
}
