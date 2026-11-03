package schema

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestCompileRejects(t *testing.T) {
	cases := map[string]string{
		"unknown keyword":           `{"type":"string","format":"email"}`,
		"unknown nested keyword":    `{"type":"object","properties":{"a":{"type":"string","oneOf":[]}}}`,
		"missing type":              `{"pattern":"^a$"}`,
		"unsupported type":          `{"type":"number"}`,
		"type list":                 `{"type":["string","integer"]}`,
		"additionalProperties true": `{"type":"object","additionalProperties":true}`,
		"additionalProperties obj":  `{"type":"object","additionalProperties":{"type":"string"}}`,
		"bad pattern":               `{"type":"string","pattern":"("}`,
		"required undeclared":       `{"type":"object","properties":{},"required":["a"]}`,
		"pattern on integer":        `{"type":"integer","pattern":"^1$"}`,
		"negative maxLength":        `{"type":"string","maxLength":-1}`,
		"fractional minLength":      `{"type":"string","minLength":1.5}`,
		"empty enum":                `{"type":"string","enum":[]}`,
		"enum wrong type":           `{"type":"string","enum":[1]}`,
		"not an object":             `[]`,
		"invalid json":              `{`,
		"items on string":           `{"type":"string","items":{"type":"string"}}`,
		"description not string":    `{"type":"string","description":1}`,
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Compile([]byte(doc)); err == nil {
				t.Fatalf("Compile(%s) succeeded, want error", doc)
			}
		})
	}
}

const paramsSchema = `{
  "type": "object",
  "additionalProperties": false,
  "required": ["name", "count"],
  "properties": {
    "name": {"type": "string", "pattern": "^[a-z][a-z0-9-]*$", "minLength": 2, "maxLength": 8, "description": "x"},
    "count": {"type": "integer", "minimum": 1, "maximum": 500},
    "mode": {"type": "string", "enum": ["fast", "slow"]},
    "force": {"type": "boolean"},
    "tags": {"type": "array", "items": {"type": "string", "maxLength": 3}}
  }
}`

func decode(t *testing.T, s string) any {
	t.Helper()
	var v any
	dec := json.NewDecoder(bytes.NewReader([]byte(s)))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestValidate(t *testing.T) {
	s, err := Compile([]byte(paramsSchema))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		value   string
		wantErr string
	}{
		{"valid minimal", `{"name":"ab","count":1}`, ""},
		{"valid full", `{"name":"ab-1","count":500,"mode":"slow","force":true,"tags":["a","bcd"]}`, ""},
		{"not object", `"ab"`, "must be of type object"},
		{"missing required", `{"name":"ab"}`, `missing required property "count"`},
		{"extra property", `{"name":"ab","count":1,"x":1}`, `unexpected property "x"`},
		{"pattern mismatch", `{"name":"Ab","count":1}`, "does not match pattern"},
		{"pattern injection", `{"name":"ab;rm","count":1}`, "does not match pattern"},
		{"too short", `{"name":"a","count":1}`, "shorter than 2"},
		{"too long", `{"name":"abcdefghi","count":1}`, "longer than 8"},
		{"string for integer", `{"name":"ab","count":"1"}`, "must be of type integer"},
		{"fraction for integer", `{"name":"ab","count":1.5}`, "must be of type integer"},
		{"below minimum", `{"name":"ab","count":0}`, "less than minimum"},
		{"above maximum", `{"name":"ab","count":501}`, "greater than maximum"},
		{"enum miss", `{"name":"ab","count":1,"mode":"medium"}`, "not one of the allowed values"},
		{"boolean wrong type", `{"name":"ab","count":1,"force":"yes"}`, "must be of type boolean"},
		{"array item invalid", `{"name":"ab","count":1,"tags":["abcd"]}`, "tags[0]"},
		{"array wrong type", `{"name":"ab","count":1,"tags":"a"}`, "must be of type array"},
		{"null value", `{"name":null,"count":1}`, "must be of type string"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := s.Validate(decode(t, tc.value))
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestValidateFloat64Numbers(t *testing.T) {
	s, err := Compile([]byte(`{"type":"integer","minimum":1,"enum":[1,2]}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Validate(float64(2)); err != nil {
		t.Fatal(err)
	}
	if err := s.Validate(float64(3)); err == nil {
		t.Fatal("want enum error")
	}
	if err := s.Validate(2.5); err == nil {
		t.Fatal("want type error")
	}
}

func TestMaxLengthCountsCharacters(t *testing.T) {
	s, err := Compile([]byte(`{"type":"string","maxLength":2}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Validate("éé"); err != nil {
		t.Fatalf("two characters rejected: %v", err)
	}
}
