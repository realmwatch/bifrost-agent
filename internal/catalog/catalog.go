// Package catalog loads the operation definitions compiled into the agent,
// checks them strictly, expands their argument lists and exports the
// hub-facing catalog and the sudo rules.
package catalog

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/realmwatch/bifrost-agent/internal/schema"
	"github.com/realmwatch/bifrost-agent/operations"
)

// Package managers the definitions map argument lists for.
const (
	PackageManagerApt = "apt"
	PackageManagerDnf = "dnf"
)

// PackageManagers lists every supported package manager.
var PackageManagers = []string{PackageManagerApt, PackageManagerDnf}

// Health checks implemented in Go, with the arguments each one takes.
var healthChecks = map[string][]string{
	"package_version": {"name", "version"},
	"service_state":   {"state", "unit"},
}

// Tier is a risk tier. Higher is riskier.
type Tier int

// Risk tiers, lowest first.
const (
	TierLow Tier = iota
	TierMedium
	TierHigh
	TierCritical
)

var tierNames = []string{"low", "medium", "high", "critical"}

func (t Tier) String() string {
	if t < 0 || int(t) >= len(tierNames) {
		return "unknown"
	}
	return tierNames[t]
}

// ParseTier parses a tier name.
func ParseTier(s string) (Tier, error) {
	for i, n := range tierNames {
		if n == s {
			return Tier(i), nil
		}
	}
	return 0, fmt.Errorf("unknown risk tier %q", s)
}

// HealthSpec names a Go health check and its templated arguments.
type HealthSpec struct {
	Check string            `json:"check"`
	Args  map[string]string `json:"args"`
}

type agentPart struct {
	Privileged bool                         `json:"privileged"`
	Argv       map[string][]string          `json:"argv"`
	DryRunArgv map[string][]string          `json:"dry_run_argv"`
	Env        map[string]map[string]string `json:"env"`
	Sudo       map[string]string            `json:"sudo"`
	Health     HealthSpec                   `json:"health"`
}

type fileDef struct {
	Name         string          `json:"name"`
	Version      int             `json:"version"`
	Description  string          `json:"description"`
	MinTier      string          `json:"min_tier"`
	Params       json.RawMessage `json:"params"`
	Rollback     *string         `json:"rollback"`
	Irreversible bool            `json:"irreversible"`
	HealthCheck  string          `json:"health_check"`
	FilesWritten []string        `json:"files_written"`
	Agent        agentPart       `json:"agent"`
}

// Definition is one checked operation definition.
type Definition struct {
	Name         string
	Version      int
	Description  string
	MinTier      Tier
	ParamsRaw    json.RawMessage
	Params       *schema.Schema
	Rollback     string
	Irreversible bool
	HealthCheck  string
	FilesWritten []string

	Privileged bool
	Argv       map[string][]string
	DryRunArgv map[string][]string
	Env        map[string]map[string]string
	Sudo       map[string]string
	Health     HealthSpec
}

// Key returns name@version.
func (d *Definition) Key() string { return Key(d.Name, d.Version) }

// Key formats an operation key.
func Key(name string, version int) string { return fmt.Sprintf("%s@%d", name, version) }

// Catalog is the set of compiled-in operations.
type Catalog struct {
	defs map[string]*Definition
}

var (
	nameRe        = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)
	placeholderRe = regexp.MustCompile(`\{([a-z_][a-z0-9_]*)\}`)
	fileRe        = regexp.MustCompile(`^(.+)@([0-9]+)\.json$`)
	envNameRe     = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
)

// Embedded loads the definitions compiled into this binary.
func Embedded() (*Catalog, error) { return Load(operations.FS) }

// MustEmbedded is Embedded that panics: the embedded set is checked by tests.
func MustEmbedded() *Catalog {
	c, err := Embedded()
	if err != nil {
		panic(err)
	}
	return c
}

// Load reads and checks every *.json definition at the root of fsys.
func Load(fsys fs.FS) (*Catalog, error) {
	files, err := fs.Glob(fsys, "*.json")
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("catalog: no operation definitions")
	}
	c := &Catalog{defs: map[string]*Definition{}}
	for _, f := range files {
		data, err := fs.ReadFile(fsys, f)
		if err != nil {
			return nil, err
		}
		d, err := parseDefinition(data)
		if err != nil {
			return nil, fmt.Errorf("catalog: %s: %w", f, err)
		}
		m := fileRe.FindStringSubmatch(path.Base(f))
		if m == nil || m[1] != d.Name || m[2] != fmt.Sprint(d.Version) {
			return nil, fmt.Errorf("catalog: %s: file name must be %s.json", f, d.Key())
		}
		c.defs[d.Key()] = d
	}
	for _, d := range c.defs {
		if d.Rollback != "" && !c.hasName(d.Rollback) {
			return nil, fmt.Errorf("catalog: %s: rollback %q is not a known operation", d.Key(), d.Rollback)
		}
	}
	return c, nil
}

// Parse checks a single definition document. Exposed for tests.
func Parse(data []byte) (*Definition, error) { return parseDefinition(data) }

func parseDefinition(data []byte) (*Definition, error) {
	var fd fileDef
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&fd); err != nil {
		return nil, err
	}
	if !nameRe.MatchString(fd.Name) {
		return nil, fmt.Errorf("invalid name %q", fd.Name)
	}
	if fd.Version < 1 {
		return nil, fmt.Errorf("version must be at least 1")
	}
	if strings.TrimSpace(fd.Description) == "" || strings.TrimSpace(fd.HealthCheck) == "" {
		return nil, fmt.Errorf("description and health_check are required")
	}
	tier, err := ParseTier(fd.MinTier)
	if err != nil {
		return nil, err
	}
	if len(fd.Params) == 0 {
		return nil, fmt.Errorf("params schema is required")
	}
	ps, err := schema.Compile(fd.Params)
	if err != nil {
		return nil, err
	}
	if ps.Type != "object" || !ps.ClosedObject {
		return nil, fmt.Errorf("params must be an object schema with additionalProperties false")
	}
	for name, p := range ps.Properties {
		if p.Type == "string" && p.Pattern == nil && p.Enum == nil {
			return nil, fmt.Errorf("string param %q needs a pattern or enum", name)
		}
		if p.Type == "string" && p.MaxLength == nil && p.Enum == nil {
			return nil, fmt.Errorf("string param %q needs maxLength", name)
		}
		if p.Pattern != nil {
			src := p.Pattern.String()
			if !strings.HasPrefix(src, "^") || !strings.HasSuffix(src, "$") {
				return nil, fmt.Errorf("param %q pattern must be anchored with ^ and $", name)
			}
		}
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, fd.Params); err != nil {
		return nil, err
	}
	d := &Definition{
		Name: fd.Name, Version: fd.Version, Description: fd.Description, MinTier: tier,
		ParamsRaw: compact.Bytes(), Params: ps, Irreversible: fd.Irreversible,
		HealthCheck: fd.HealthCheck, FilesWritten: fd.FilesWritten,
		Privileged: fd.Agent.Privileged, Argv: fd.Agent.Argv, DryRunArgv: fd.Agent.DryRunArgv,
		Env: fd.Agent.Env, Sudo: fd.Agent.Sudo, Health: fd.Agent.Health,
	}
	if d.FilesWritten == nil {
		d.FilesWritten = []string{}
	}
	if fd.Rollback != nil {
		d.Rollback = *fd.Rollback
		if d.Irreversible {
			return nil, fmt.Errorf("an irreversible operation cannot name a rollback")
		}
	}

	for _, pm := range PackageManagers {
		argv, ok := d.Argv[pm]
		if !ok {
			return nil, fmt.Errorf("argv for %s is required", pm)
		}
		if err := checkTemplate(argv, ps); err != nil {
			return nil, fmt.Errorf("argv %s: %w", pm, err)
		}
		if d.Privileged {
			want := SudoRule(argv)
			if d.Sudo[pm] != want {
				return nil, fmt.Errorf("sudo %s must be %q", pm, want)
			}
		}
		if dr, ok := d.DryRunArgv[pm]; ok {
			if err := checkTemplate(dr, ps); err != nil {
				return nil, fmt.Errorf("dry_run_argv %s: %w", pm, err)
			}
		}
	}
	for pm := range d.Argv {
		if !knownPM(pm) {
			return nil, fmt.Errorf("unknown package manager %q in argv", pm)
		}
	}
	for pm := range d.DryRunArgv {
		if !knownPM(pm) {
			return nil, fmt.Errorf("unknown package manager %q in dry_run_argv", pm)
		}
	}
	for pm := range d.Sudo {
		if !knownPM(pm) || !d.Privileged {
			return nil, fmt.Errorf("unexpected sudo rule for %q", pm)
		}
	}
	for pm, env := range d.Env {
		if !knownPM(pm) {
			return nil, fmt.Errorf("unknown package manager %q in env", pm)
		}
		for k := range env {
			if !envNameRe.MatchString(k) {
				return nil, fmt.Errorf("invalid env name %q", k)
			}
		}
	}
	wantArgs, ok := healthChecks[d.Health.Check]
	if !ok {
		return nil, fmt.Errorf("unknown health check %q", d.Health.Check)
	}
	gotArgs := make([]string, 0, len(d.Health.Args))
	for k, v := range d.Health.Args {
		gotArgs = append(gotArgs, k)
		if err := checkElement(v, ps); err != nil {
			return nil, fmt.Errorf("health arg %s: %w", k, err)
		}
	}
	sort.Strings(gotArgs)
	if strings.Join(gotArgs, ",") != strings.Join(wantArgs, ",") {
		return nil, fmt.Errorf("health check %s takes args %v", d.Health.Check, wantArgs)
	}
	return d, nil
}

func knownPM(pm string) bool {
	for _, p := range PackageManagers {
		if p == pm {
			return true
		}
	}
	return false
}

func checkTemplate(argv []string, ps *schema.Schema) error {
	if len(argv) == 0 {
		return fmt.Errorf("must not be empty")
	}
	if !strings.HasPrefix(argv[0], "/") || strings.Contains(argv[0], "{") {
		return fmt.Errorf("argv[0] must be an absolute path without placeholders")
	}
	for _, el := range argv {
		if el == "" {
			return fmt.Errorf("empty argument")
		}
		if err := checkElement(el, ps); err != nil {
			return err
		}
	}
	return nil
}

func checkElement(el string, ps *schema.Schema) error {
	rest := placeholderRe.ReplaceAllString(el, "")
	if strings.ContainsAny(rest, "{}") {
		return fmt.Errorf("malformed placeholder in %q", el)
	}
	for _, m := range placeholderRe.FindAllStringSubmatch(el, -1) {
		p, ok := ps.Properties[m[1]]
		if !ok {
			return fmt.Errorf("placeholder {%s} is not a declared param", m[1])
		}
		if p.Type != "string" && p.Type != "integer" {
			return fmt.Errorf("placeholder {%s} must be a string or integer param", m[1])
		}
		required := false
		for _, r := range ps.Required {
			required = required || r == m[1]
		}
		if !required {
			return fmt.Errorf("placeholder {%s} must be a required param", m[1])
		}
	}
	return nil
}

// SudoRule derives the sudo command pattern for an argument list: every
// argument that holds a placeholder becomes a "*".
func SudoRule(argv []string) string {
	out := make([]string, len(argv))
	for i, el := range argv {
		if placeholderRe.MatchString(el) {
			out[i] = "*"
		} else {
			out[i] = el
		}
	}
	return strings.Join(out, " ")
}

func (c *Catalog) hasName(name string) bool {
	for _, d := range c.defs {
		if d.Name == name {
			return true
		}
	}
	return false
}

// Get returns the definition for name and version.
func (c *Catalog) Get(name string, version int) (*Definition, bool) {
	d, ok := c.defs[Key(name, version)]
	return d, ok
}

// Keys returns every name@version, sorted.
func (c *Catalog) Keys() []string {
	keys := make([]string, 0, len(c.defs))
	for k := range c.defs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Definitions returns every definition sorted by key.
func (c *Catalog) Definitions() []*Definition {
	out := make([]*Definition, 0, len(c.defs))
	for _, k := range c.Keys() {
		out = append(out, c.defs[k])
	}
	return out
}

// argvFor returns the argument list template for pm. An operation whose
// argument lists are the same for every package manager (services) also
// runs on hosts where none was detected (pm "").
func (d *Definition) argvFor(pm string) ([]string, bool) {
	if tmpl, ok := d.Argv[pm]; ok {
		return tmpl, true
	}
	if pm != "" {
		return nil, false
	}
	first := d.Argv[PackageManagers[0]]
	for _, other := range PackageManagers[1:] {
		if strings.Join(d.Argv[other], "\x00") != strings.Join(first, "\x00") {
			return nil, false
		}
	}
	return first, true
}

// Supports reports whether the operation can run with package manager pm.
func (d *Definition) Supports(pm string) bool {
	_, ok := d.argvFor(pm)
	return ok
}

// Expanded is a ready-to-run command for one operation step.
type Expanded struct {
	Argv []string
	Env  []string
	// Privileged steps run through sudo when the agent is configured to.
	Privileged bool
}

// Expand fills the argument list for the package manager with params, which
// must already have passed schema validation. Each placeholder fills part of
// exactly one argument; nothing is passed to a shell.
func (d *Definition) Expand(pm string, params map[string]any) (*Expanded, error) {
	tmpl, ok := d.argvFor(pm)
	if !ok {
		return nil, fmt.Errorf("%s has no argv for package manager %q", d.Key(), pm)
	}
	argv, err := fill(tmpl, params)
	if err != nil {
		return nil, err
	}
	return &Expanded{Argv: argv, Env: d.envFor(pm), Privileged: d.Privileged}, nil
}

// ExpandDryRun is Expand for the dry run argument list. Dry runs are never
// privileged.
func (d *Definition) ExpandDryRun(pm string, params map[string]any) (*Expanded, error) {
	tmpl, ok := d.DryRunArgv[pm]
	if !ok {
		return nil, fmt.Errorf("%s has no dry run for %s", d.Key(), pm)
	}
	argv, err := fill(tmpl, params)
	if err != nil {
		return nil, err
	}
	return &Expanded{Argv: argv, Env: d.envFor(pm)}, nil
}

// HealthArgs fills the health check arguments with params.
func (d *Definition) HealthArgs(params map[string]any) (map[string]string, error) {
	out := map[string]string{}
	for k, v := range d.Health.Args {
		s, err := fillOne(v, params)
		if err != nil {
			return nil, err
		}
		out[k] = s
	}
	return out, nil
}

func (d *Definition) envFor(pm string) []string {
	env := d.Env[pm]
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k+"="+env[k])
	}
	return out
}

func fill(tmpl []string, params map[string]any) ([]string, error) {
	out := make([]string, len(tmpl))
	for i, el := range tmpl {
		s, err := fillOne(el, params)
		if err != nil {
			return nil, err
		}
		out[i] = s
	}
	return out, nil
}

func fillOne(el string, params map[string]any) (string, error) {
	var ferr error
	s := placeholderRe.ReplaceAllStringFunc(el, func(m string) string {
		name := m[1 : len(m)-1]
		v, ok := params[name]
		if !ok {
			ferr = fmt.Errorf("missing param %q", name)
			return ""
		}
		switch tv := v.(type) {
		case string:
			return tv
		case json.Number:
			return tv.String()
		case float64:
			return fmt.Sprintf("%d", int64(tv))
		default:
			ferr = fmt.Errorf("param %q must be a string or integer", name)
			return ""
		}
	})
	if ferr != nil {
		return "", ferr
	}
	if el != s {
		if s == "" || strings.HasPrefix(s, "-") || strings.ContainsRune(s, 0) {
			return "", fmt.Errorf("argument %q would be empty, start with '-' or hold NUL", s)
		}
	}
	return s, nil
}
