// Answer "what do I send, and what comes back" for every route, from the
// source that decides it.
//
// extract-routes.py reads the router and answers what exists and who may call
// it. That is the question a routing table can answer, and it stops there:
// whether common_name is required, that supplying csr_pem makes it optional,
// and that a gateway returning rubbish produces a 502 rather than a stored
// record are all facts about the handler, invisible from the router.
//
// So this reads the handlers. It is an AST parse rather than a regular
// expression over the same files because the failure mode of a regex here is
// silence: a struct it does not recognise becomes an endpoint documented as
// taking no body at all, which is worse than the omission it replaced. Every
// resolution failure below is therefore fatal — a request type this cannot
// follow stops the build instead of quietly publishing an empty table.
//
// Reads the route inventory on stdin and writes the finished one to -o:
//
//	python3 scripts/extract-routes.py | go run scripts/schemagen/main.go -o docs/routes.json
//
// Deliberately not in place, and deliberately not the same file the first pass
// wrote. When this one fails — which it is designed to do, loudly, on anything
// it cannot resolve — the checked-in inventory has to be exactly what it was
// before the command ran. An earlier version had extract-routes.py write the
// target first and this one rewrite it, so a failure here left a file that was
// valid JSON, listed every route, and was missing the half the API reference is
// generated from (#50).
package main

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
)

const (
	apiDir   = "core/api"
	storeDir = "core/store"
	routerGo = "core/api/router.go"

	// agentSDK is a dependency now rather than a directory. #44 moved it to its
	// own repository, so the file this reads lives in the module cache and its
	// path depends on the version core/go.mod resolves.
	agentSDK      = "github.com/certpilot/certpilot-agent-sdk"
	agentAuthFile = "agentauth/agentauth.go"
)

// ── Output shapes ─────────────────────────────────────────────────────────

type Field struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	GoType     string `json:"go_type,omitempty"`
	Required   bool   `json:"required"`
	Constraint string `json:"constraint,omitempty"`
	// Value is set when the handler sends a literal rather than a variable,
	// which is how a fixed confirmation string reaches the page as the string
	// it is instead of as an untyped "any".
	Value string `json:"value,omitempty"`
	Doc   string `json:"doc,omitempty"`
}

type Schema struct {
	Name   string  `json:"name"`
	Doc    string  `json:"doc,omitempty"`
	Fields []Field `json:"fields"`
}

type Response struct {
	Status int      `json:"status"`
	Shape  string   `json:"shape,omitempty"`
	Model  string   `json:"model,omitempty"`
	Keys   []Field  `json:"keys,omitempty"`
	Errors []string `json:"errors,omitempty"`
}

type QueryParam struct {
	Name    string `json:"name"`
	Default string `json:"default,omitempty"`
}

// ── Parsed package index ──────────────────────────────────────────────────

type structDef struct {
	name string
	doc  string
	node *ast.StructType
	// imports of the file it was declared in, so a field whose type comes from
	// somewhere else can still be followed.
	imports map[string]string
}

type handlerFn struct {
	decl    *ast.FuncDecl
	imports map[string]string
}

type index struct {
	fset    *token.FileSet
	structs map[string]*structDef // "api.RequestCertificateInput"
	funcs   map[string]*handlerFn // "CertificateHandler.Create"
	ctors   map[string]string     // NewCertificateHandler -> CertificateHandler
	loaded  map[string]string     // dir -> package name
	// storeResults maps a Store interface method to the types it returns, so
	// `c.JSON(200, cert)` can say what `cert` is. All of them, in order:
	// `certs, total, err := h.store.ListCertificates(...)` documents `total`
	// as an integer only if the second result is read too.
	storeResults map[string][]string
}

func main() {
	outPath, inPath := parseArgs(os.Args[1:])

	ix := &index{
		fset:         token.NewFileSet(),
		structs:      map[string]*structDef{},
		funcs:        map[string]*handlerFn{},
		ctors:        map[string]string{},
		loaded:       map[string]string{},
		storeResults: map[string][]string{},
	}
	ix.loadDir(apiDir)
	ix.loadDir(storeDir)
	ix.loadStoreInterface()

	// certHandler -> CertificateHandler, from the router's own wiring. Without
	// it the handler names in routes.json ("certHandler.Create") cannot be
	// matched to the method that implements them.
	vars := ix.handlerVars()

	raw, err := readInput(inPath)
	if err != nil {
		fatal("%v — the input is extract-routes.py's output", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		fatal("%s: %v", inPath, err)
	}
	routes, _ := doc["routes"].([]any)
	if len(routes) == 0 {
		fatal("%s has no routes", inPath)
	}

	used := map[string]bool{}
	var described, inline int

	for _, r := range routes {
		route, _ := r.(map[string]any)
		handler, _ := route["handler"].(string)
		if handler == "" {
			inline++ // an inline closure in the router; nothing to read
			continue
		}
		recv, method, ok := strings.Cut(handler, ".")
		if !ok {
			fatal("handler %q is not var.Method", handler)
		}
		typeName, ok := vars[recv]
		if !ok {
			fatal("handler %q: no constructor for %q in %s", handler, recv, routerGo)
		}
		fn, ok := ix.funcs[typeName+"."+method]
		if !ok {
			fatal("handler %q resolves to %s.%s, which does not exist", handler, typeName, method)
		}

		info := ix.analyse(fn, used)
		if info.Request != nil {
			route["request"] = info.Request
		}
		if len(info.Responses) > 0 {
			route["responses"] = info.Responses
		}
		if len(info.QueryParams) > 0 {
			route["query_params"] = info.QueryParams
		}
		if len(info.PathParams) > 0 {
			route["path_params"] = info.PathParams
		}
		described++
	}

	// The models a response names, so a reader following "returns a
	// Certificate" has somewhere to arrive. Only the referenced ones: the
	// store defines plenty the API never returns.
	models := map[string]*Schema{}
	for name := range used {
		for _, pkg := range []string{"store.", "api."} {
			if def, ok := ix.structs[pkg+name]; ok {
				models[name] = ix.schema(def)
				break
			}
		}
	}
	if len(models) > 0 {
		doc["models"] = models
	}
	doc["auth_schemes"] = authSchemes()

	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		fatal("%v", err)
	}
	if err := writeAtomic(outPath, append(out, '\n')); err != nil {
		fatal("%v", err)
	}
	fmt.Printf("schemagen: %d routes described, %d inline handlers, %d models\n",
		described, inline, len(models))
}

// authSchemes describes how a caller proves who it is, per scheme.
//
// The agent headers are read out of pkg/agentauth rather than written here.
// Documenting a signed API means naming three headers exactly, and a name
// that is nearly right is worse than no example at all: it fails with a 403
// that says the request was not accepted as coming from an enrolled agent,
// which sends the reader looking at their key material rather than at their
// spelling.
func authSchemes() map[string]any {
	agentAuth := filepath.Join(mustModuleDir(agentSDK), agentAuthFile)
	src, err := os.ReadFile(agentAuth)
	if err != nil {
		fatal("%v", err)
	}
	f, err := parser.ParseFile(token.NewFileSet(), agentAuth, src, parser.ParseComments)
	if err != nil {
		fatal("%v", err)
	}

	headers := map[string]string{}
	ast.Inspect(f, func(n ast.Node) bool {
		vs, ok := n.(*ast.ValueSpec)
		if !ok || len(vs.Names) != 1 || len(vs.Values) != 1 {
			return true
		}
		if v, ok := str(vs.Values[0]); ok {
			headers[vs.Names[0].Name] = v
		}
		return true
	})

	agent := make([]map[string]string, 0, 3)
	for _, want := range []struct{ constant, placeholder string }{
		{"AgentHeader", "<agent id>"},
		{"TimestampHeader", "<unix seconds>"},
		{"SignatureHeader", "<base64 ed25519 signature>"},
	} {
		name, ok := headers[want.constant]
		if !ok {
			fatal("%s does not declare %s — has the signing scheme changed?",
				agentAuth, want.constant)
		}
		agent = append(agent, map[string]string{"name": name, "value": want.placeholder})
	}

	return map[string]any{
		"bearer": map[string]any{
			"headers": []map[string]string{
				{"name": "Authorization", "value": "Bearer <token>"},
			},
		},
		"agent-signature": map[string]any{"headers": agent},
		// Deliberately no headers. The enrolment token is a field in the
		// request body, and an example inventing a header for it would be
		// documenting an endpoint that does not exist.
		"agent-enrolment-token": map[string]any{
			"headers": []map[string]string{},
			"note":    "The enrolment token is sent as `token` in the request body, not as a header.",
		},
		"none": map[string]any{"headers": []map[string]string{}},
	}
}

// ── Loading ───────────────────────────────────────────────────────────────

// loadDir parses one package and indexes its structs, methods and
// constructors. Idempotent: a package reached from two imports is read once.
func (ix *index) loadDir(dir string) string {
	if pkg, ok := ix.loaded[dir]; ok {
		return pkg
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		fatal("%v — run this from the repository root", err)
	}
	var files []string
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		files = append(files, filepath.Join(dir, name))
	}
	sort.Strings(files)
	if len(files) == 0 {
		fatal("no Go files in %s", dir)
	}

	var pkgName string
	// Recorded before parsing, so a package that imports itself transitively
	// cannot recurse for ever.
	ix.loaded[dir] = ""

	for _, path := range files {
		f, err := parser.ParseFile(ix.fset, path, nil, parser.ParseComments)
		if err != nil {
			fatal("%v", err)
		}
		pkgName = f.Name.Name
		imports := importMap(f)

		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					ts, ok := spec.(*ast.TypeSpec)
					if !ok {
						continue
					}
					st, ok := ts.Type.(*ast.StructType)
					if !ok {
						continue
					}
					// A single-type declaration carries its comment on the
					// GenDecl rather than the TypeSpec.
					doc := ts.Doc.Text()
					if doc == "" {
						doc = d.Doc.Text()
					}
					ix.structs[pkgName+"."+ts.Name.Name] = &structDef{
						name: ts.Name.Name, doc: clean(doc), node: st, imports: imports,
					}
				}
			case *ast.FuncDecl:
				if d.Recv != nil && len(d.Recv.List) == 1 {
					key := bare(d.Recv.List[0].Type) + "." + d.Name.Name
					ix.funcs[key] = &handlerFn{decl: d, imports: imports}
					continue
				}
				// `func NewCertificateHandler(...) *CertificateHandler`
				if strings.HasPrefix(d.Name.Name, "New") && d.Type.Results != nil &&
					len(d.Type.Results.List) == 1 {
					ix.ctors[d.Name.Name] = bare(d.Type.Results.List[0].Type)
				}
			}
		}
	}
	ix.loaded[dir] = pkgName
	return pkgName
}

func importMap(f *ast.File) map[string]string {
	out := map[string]string{}
	for _, imp := range f.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			continue
		}
		name := path[strings.LastIndex(path, "/")+1:]
		if imp.Name != nil {
			name = imp.Name.Name
		}
		out[name] = path
	}
	return out
}

// sourceModules maps a module path prefix to where that module's source sits.
//
// An empty value means "in this tree, at the path that follows the prefix".
// Anything else is resolved through the module cache, because the two SDKs are
// separate repositories now — #43 and #44 — and a type that lives in one of
// them is genuinely outside this checkout while still being source this
// generator has to read.
//
// It has changed shape twice for the same underlying reason. It was one prefix
// and a strings.TrimPrefix; #42 split pkg into three modules whose paths were
// the repositories they would live in, and a type that had moved reported as
// "outside this module" — true of the path and false of the source. Now they
// have actually moved, and the answer is a lookup rather than a mapping to a
// directory that no longer exists.
//
// Request types live in five packages and counting, so the import list of the
// file that binds them is what says where to look. Anything genuinely outside
// is reported rather than skipped.
var sourceModules = map[string]string{
	"github.com/certpilot/certpilot/":             "",
	"github.com/certpilot/certpilot-gateway-sdk/": agentSDKCache,
	"github.com/certpilot/certpilot-agent-sdk/":   agentSDKCache,
}

// agentSDKCache marks a prefix whose source is resolved through `go list`
// rather than being a path in this tree.
const agentSDKCache = "\x00module-cache"

// moduleDirs caches `go list -m` answers. The command is not fast and the same
// module is asked for once per type that lives in it.
var moduleDirs = map[string]string{}

// mustModuleDir resolves a module path to the directory holding its source,
// through the module cache, and fails loudly rather than returning a guess.
//
// Run from core/, which is the module that requires both SDKs. Running it from
// the repository root would ask a go.work-rooted question and get a different
// answer, or none.
func mustModuleDir(modPath string) string {
	if dir, ok := moduleDirs[modPath]; ok {
		return dir
	}
	dir := listModuleDir(modPath)
	if dir == "" {
		// `go list -m -f {{.Dir}}` answers with an empty string, not an error,
		// for a module that is required but not yet in the cache. That is the
		// normal state of a fresh checkout, so downloading is part of resolving
		// rather than an error path — the first CI run after the SDKs moved out
		// failed here, on a clean runner, having worked on a laptop that had
		// already downloaded them.
		out, err := runInCore("go", "mod", "download", modPath)
		if err != nil {
			fatal("could not download %s, which holds source this generator reads: %v\n%s",
				modPath, err, out)
		}
		dir = listModuleDir(modPath)
	}
	if dir == "" {
		fatal("go list still reports no directory for %s after downloading it", modPath)
	}
	moduleDirs[modPath] = dir
	return dir
}

// listModuleDir asks where a module's source is, returning "" when the answer
// is "nowhere yet".
func listModuleDir(modPath string) string {
	out, err := runInCore("go", "list", "-m", "-f", "{{.Dir}}", modPath)
	if err != nil {
		fatal("could not locate the source of %s, which is a dependency now rather than "+
			"a directory in this tree: %v\n%s", modPath, err, out)
	}
	return strings.TrimSpace(out)
}

// runInCore runs a go command from core/, the module that requires both SDKs.
// Running from the repository root would ask a go.work-rooted question and get
// a different answer, or none.
func runInCore(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.Dir = "core"
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// inTreeDir resolves an import path to a directory on disk, or reports that it
// cannot. The name is historical: it now resolves out-of-tree sources too.
func inTreeDir(path string) (string, bool) {
	for prefix, where := range sourceModules {
		if !strings.HasPrefix(path, prefix) {
			continue
		}
		rest := strings.TrimPrefix(path, prefix)
		if where == agentSDKCache {
			return filepath.Join(mustModuleDir(strings.TrimSuffix(prefix, "/")), rest), true
		}
		return where + rest, true
	}
	return "", false
}

// resolveStruct follows `fleet.Request` to the package that declares it, using
// the import list of the file that referred to it.
func (ix *index) resolveStruct(typeName string, imports map[string]string) (*structDef, string) {
	typeName = strings.TrimPrefix(strings.TrimPrefix(typeName, "[]"), "*")
	pkg, name, qualified := strings.Cut(typeName, ".")
	if !qualified {
		// Unqualified: the handler's own package.
		def, ok := ix.structs["api."+typeName]
		if !ok {
			return nil, fmt.Sprintf("%q is not a struct in %s", typeName, apiDir)
		}
		return def, ""
	}
	if def, ok := ix.structs[pkg+"."+name]; ok {
		return def, ""
	}
	path, ok := imports[pkg]
	if !ok {
		return nil, fmt.Sprintf("package %q is not imported by the file that binds %s", pkg, typeName)
	}
	dir, ok := inTreeDir(path)
	if !ok {
		return nil, fmt.Sprintf(
			"%s comes from %s, which is not a module this repository builds", typeName, path)
	}
	ix.loadDir(dir)
	def, ok := ix.structs[pkg+"."+name]
	if !ok {
		return nil, fmt.Sprintf("%s was not found in %s", typeName, path)
	}
	return def, ""
}

// loadStoreInterface records what each Store method returns, which is how a
// bare `c.JSON(200, cert)` gets a name attached to it.
func (ix *index) loadStoreInterface() {
	f, err := parser.ParseFile(ix.fset, filepath.Join(storeDir, "store.go"), nil, parser.ParseComments)
	if err != nil {
		fatal("%v", err)
	}
	ast.Inspect(f, func(n ast.Node) bool {
		ts, ok := n.(*ast.TypeSpec)
		if !ok || ts.Name.Name != "Store" {
			return true
		}
		it, ok := ts.Type.(*ast.InterfaceType)
		if !ok {
			return true
		}
		for _, m := range it.Methods.List {
			ft, ok := m.Type.(*ast.FuncType)
			if !ok || ft.Results == nil || len(ft.Results.List) == 0 || len(m.Names) != 1 {
				continue
			}
			var results []string
			for _, r := range ft.Results.List {
				// `(a, b string)` declares two results from one field.
				n := len(r.Names)
				if n == 0 {
					n = 1
				}
				for range n {
					results = append(results, goType(r.Type))
				}
			}
			ix.storeResults[m.Names[0].Name] = results
		}
		return false
	})
	if len(ix.storeResults) == 0 {
		fatal("no methods found on store.Store — has the interface been renamed?")
	}
}

// handlerVars reads `certHandler := NewCertificateHandler(...)` out of the
// router and resolves each variable to the type it holds.
func (ix *index) handlerVars() map[string]string {
	f, err := parser.ParseFile(ix.fset, routerGo, nil, parser.ParseComments)
	if err != nil {
		fatal("%v", err)
	}
	vars := map[string]string{}
	ast.Inspect(f, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			return true
		}
		name, ok := as.Lhs[0].(*ast.Ident)
		if !ok {
			return true
		}
		call, ok := as.Rhs[0].(*ast.CallExpr)
		if !ok {
			return true
		}
		fn, ok := call.Fun.(*ast.Ident)
		if !ok {
			return true
		}
		if t, ok := ix.ctors[fn.Name]; ok {
			vars[name.Name] = t
		}
		return true
	})
	if len(vars) == 0 {
		fatal("no handler constructors found in %s", routerGo)
	}
	return vars
}

// ── Analysis ──────────────────────────────────────────────────────────────

type handlerInfo struct {
	Request     *Schema
	Responses   []Response
	QueryParams []QueryParam
	PathParams  []string
}

func (ix *index) analyse(h *handlerFn, used map[string]bool) handlerInfo {
	var info handlerInfo
	fn := h.decl
	if fn.Body == nil {
		return info
	}

	// Local variables, so an identifier handed to c.JSON can be named. Three
	// sources: an explicit `var x T`, `certs, total, err := h.store.List...()`,
	// and a literal the handler assembles before sending it.
	locals := map[string]string{}
	// Response envelopes built as `body := gin.H{...}`, whose keys are then
	// added to conditionally. Tracked separately because the interesting part
	// is the key set, not the type, and because a handler that attaches
	// policy violations only when it found some would otherwise be documented
	// as never returning them at all.
	envelopes := map[string][]Field{}

	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.DeclStmt:
			gd, ok := s.Decl.(*ast.GenDecl)
			if !ok {
				return true
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok || vs.Type == nil {
					continue
				}
				for _, name := range vs.Names {
					locals[name.Name] = goType(vs.Type)
				}
			}

		case *ast.AssignStmt:
			// `body["policy_violations"] = violations`
			if len(s.Lhs) == 1 && len(s.Rhs) == 1 {
				if ie, ok := s.Lhs[0].(*ast.IndexExpr); ok {
					if id, ok := ie.X.(*ast.Ident); ok {
						if keys, tracked := envelopes[id.Name]; tracked {
							if key, ok := str(ie.Index); ok {
								envelopes[id.Name] = append(keys, field(key, s.Rhs[0], locals))
							}
						}
					}
					return true
				}
			}

			if call, ok := single[*ast.CallExpr](s.Rhs); ok {
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				results, ok := ix.storeResults[sel.Sel.Name]
				if !ok {
					return true
				}
				for i, lhs := range s.Lhs {
					id, ok := lhs.(*ast.Ident)
					if !ok || id.Name == "_" || i >= len(results) {
						continue
					}
					locals[id.Name] = results[i]
				}
				return true
			}

			// `body := gin.H{...}`, `certRecord := &store.Certificate{...}`
			if len(s.Lhs) != 1 || len(s.Rhs) != 1 {
				return true
			}
			id, ok := s.Lhs[0].(*ast.Ident)
			if !ok {
				return true
			}
			rhs := s.Rhs[0]
			if u, ok := rhs.(*ast.UnaryExpr); ok {
				rhs = u.X
			}
			lit, ok := rhs.(*ast.CompositeLit)
			if !ok || lit.Type == nil {
				return true
			}
			if isGinH(lit.Type) {
				envelopes[id.Name] = ginKeys(lit, locals)
				return true
			}
			locals[id.Name] = goType(lit.Type)
		}
		return true
	})

	byStatus := map[int]*Response{}
	queries := map[string]QueryParam{}
	params := map[string]bool{}

	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		// `unexpectedQuery(c, "status", "environment")` is the declared
		// allow-list and more trustworthy than scraping c.Query calls: it is
		// what the endpoint promises to understand, and the guard that
		// refuses anything else.
		if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "unexpectedQuery" {
			for _, a := range call.Args[1:] {
				if s, ok := str(a); ok {
					queries[s] = QueryParam{Name: s}
				}
			}
			return true
		}

		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if recv, _ := sel.X.(*ast.Ident); recv == nil || recv.Name != "c" {
			return true
		}
		if len(call.Args) == 0 {
			return true
		}

		switch sel.Sel.Name {
		case "ShouldBindJSON":
			unary, ok := call.Args[0].(*ast.UnaryExpr)
			if !ok {
				return true
			}
			id, ok := unary.X.(*ast.Ident)
			if !ok {
				return true
			}
			typeName, ok := locals[id.Name]
			if !ok {
				fatal("%s: cannot resolve the type bound by ShouldBindJSON(&%s)",
					fn.Name.Name, id.Name)
			}
			def, why := ix.resolveStruct(typeName, h.imports)
			if def == nil {
				fatal("%s: ShouldBindJSON binds %s", fn.Name.Name, why)
			}
			info.Request = ix.schema(def)

		case "Param":
			if s, ok := str(call.Args[0]); ok {
				params[s] = true
			}

		case "Query":
			// display_token is a credential a wall screen presents in the
			// query string, not a filter. It is exempted in unexpectedQuery
			// for that reason and does not belong in a parameter table.
			if s, ok := str(call.Args[0]); ok && s != "display_token" {
				if _, exists := queries[s]; !exists {
					queries[s] = QueryParam{Name: s}
				}
			}

		case "DefaultQuery":
			if len(call.Args) == 2 {
				if s, ok := str(call.Args[0]); ok {
					d, _ := str(call.Args[1])
					queries[s] = QueryParam{Name: s, Default: d}
				}
			}

		case "JSON":
			if len(call.Args) != 2 {
				return true
			}
			code, ok := statusCode(call.Args[0])
			if !ok {
				return true
			}
			// One entry per status, merged rather than first-wins. A handler
			// emits 400 from a dozen places and repeating the row twelve
			// times helps nobody, but the *reasons* differ and every one of
			// them is a thing this endpoint will actually say — which is the
			// question a caller staring at a 400 is trying to answer.
			r := ix.describe(code, call.Args[1], locals, envelopes, used)
			prev, ok := byStatus[code]
			if !ok {
				byStatus[code] = &r
				return true
			}
			if prev.Shape == "" && r.Shape != "" {
				prev.Shape, prev.Model, prev.Keys = r.Shape, r.Model, r.Keys
			}
			for _, msg := range r.Errors {
				if !slices.Contains(prev.Errors, msg) {
					prev.Errors = append(prev.Errors, msg)
				}
			}
		}
		return true
	})

	for _, r := range byStatus {
		info.Responses = append(info.Responses, *r)
	}
	sort.Slice(info.Responses, func(i, j int) bool {
		return info.Responses[i].Status < info.Responses[j].Status
	})
	for name := range params {
		info.PathParams = append(info.PathParams, name)
	}
	sort.Strings(info.PathParams)
	for _, q := range queries {
		info.QueryParams = append(info.QueryParams, q)
	}
	sort.Slice(info.QueryParams, func(i, j int) bool {
		return info.QueryParams[i].Name < info.QueryParams[j].Name
	})
	return info
}

// describe says what a c.JSON body actually is.
func (ix *index) describe(code int, arg ast.Expr, locals map[string]string,
	envelopes map[string][]Field, used map[string]bool) Response {

	resp := Response{Status: code}
	var keys []Field

	switch v := arg.(type) {
	case *ast.CompositeLit:
		// A declared response struct, sent literally. GET /me answers this
		// way, and it is the endpoint the UI trusts for a role, so an empty
		// row here is not an acceptable outcome.
		if !isGinH(v.Type) {
			t := goType(v.Type)
			if m := modelName(t); m != "" {
				resp.Shape, resp.Model = m, m
				used[m] = true
			}
			return resp
		}
		keys = ginKeys(v, locals)

	case *ast.Ident:
		if k, ok := envelopes[v.Name]; ok {
			keys = k
			break
		}
		t, ok := locals[v.Name]
		if !ok {
			return resp
		}
		resp.Shape = docType(t)
		if m := modelName(t); m != "" {
			resp.Model = m
			used[m] = true
		}
		return resp
	}

	for _, k := range keys {
		// A literal error message is the most useful thing on the page: it is
		// the string the caller will actually read at 2am. `err.Error()` is
		// not one, and is left out rather than guessed at.
		if k.Name == "error" {
			if k.Value != "" {
				resp.Errors = append(resp.Errors, k.Value)
			}
			continue
		}
		if m := modelName(k.GoType); m != "" {
			used[m] = true
		}
		resp.Keys = append(resp.Keys, k)
	}
	sort.Slice(resp.Keys, func(i, j int) bool { return resp.Keys[i].Name < resp.Keys[j].Name })
	if len(resp.Keys) > 0 {
		resp.Shape = "object"
	}
	return resp
}

func isGinH(e ast.Expr) bool {
	sel, ok := e.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "H"
}

// ginKeys reads the keys out of a gin.H literal. A literal string value is
// carried in Doc, which is how an error message reaches the page.
func ginKeys(lit *ast.CompositeLit, locals map[string]string) []Field {
	var out []Field
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := str(kv.Key)
		if !ok {
			continue
		}
		out = append(out, field(key, kv.Value, locals))
	}
	return out
}

func field(name string, value ast.Expr, locals map[string]string) Field {
	f := Field{Name: name, Type: "any"}
	if s, ok := str(value); ok {
		f.Value = s
		f.Type = "string"
		return f
	}
	if id, ok := value.(*ast.Ident); ok {
		if t, ok := locals[id.Name]; ok {
			f.GoType = t
			f.Type = docType(t)
		}
	}
	return f
}

// ── Struct rendering ──────────────────────────────────────────────────────

func (ix *index) schema(def *structDef) *Schema {
	s := &Schema{Name: def.name, Doc: def.doc, Fields: []Field{}}
	for _, f := range def.node.Fields.List {
		if f.Tag == nil || len(f.Names) == 0 {
			continue // embedded, or unexported with no wire presence
		}
		tag := reflect.StructTag(strings.Trim(f.Tag.Value, "`"))
		jsonTag := tag.Get("json")
		if jsonTag == "-" || jsonTag == "" {
			continue
		}
		name := strings.Split(jsonTag, ",")[0]
		if name == "" {
			continue
		}
		binding := tag.Get("binding")
		doc := f.Doc.Text()
		if doc == "" {
			doc = f.Comment.Text()
		}
		gt := goType(f.Type)
		s.Fields = append(s.Fields, Field{
			Name:       name,
			Type:       docType(gt),
			GoType:     gt,
			Required:   hasRule(binding, "required"),
			Constraint: constraint(binding),
			Doc:        clean(doc),
		})
	}
	return s
}

// ── Small helpers ─────────────────────────────────────────────────────────

// goType renders a type expression back to something close to its source form.
func goType(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return "*" + goType(t.X)
	case *ast.ArrayType:
		return "[]" + goType(t.Elt)
	case *ast.MapType:
		return "map[" + goType(t.Key) + "]" + goType(t.Value)
	case *ast.SelectorExpr:
		return goType(t.X) + "." + t.Sel.Name
	case *ast.InterfaceType:
		return "any"
	case *ast.StructType:
		return "struct"
	case *ast.Ellipsis:
		return "..." + goType(t.Elt)
	case *ast.FuncType:
		return "func"
	case *ast.ChanType:
		return "chan"
	}
	return "any"
}

// docType maps a Go type onto what a caller actually sees on the wire.
func docType(g string) string {
	g = strings.TrimPrefix(g, "*")
	switch {
	case strings.HasPrefix(g, "[]"):
		return docType(g[2:]) + "[]"
	case strings.HasPrefix(g, "map["):
		return "object"
	}
	switch g {
	case "string":
		return "string"
	case "bool":
		return "boolean"
	case "int", "int8", "int16", "int32", "int64", "uint", "uint32", "uint64":
		return "integer"
	case "float32", "float64":
		return "number"
	case "any", "interface{}":
		return "any"
	case "time.Time":
		return "timestamp"
	case "json.RawMessage":
		return "object"
	}
	// A named type: report the bare name, the models table has its fields.
	if i := strings.LastIndex(g, "."); i >= 0 {
		return g[i+1:]
	}
	return g
}

// modelName picks the model out of a type, if there is one.
func modelName(g string) string {
	g = strings.TrimPrefix(g, "*")
	g = strings.TrimPrefix(g, "[]")
	g = strings.TrimPrefix(g, "*")
	if strings.HasPrefix(g, "map[") {
		return ""
	}
	if i := strings.LastIndex(g, "."); i >= 0 {
		g = g[i+1:]
	}
	if g == "" || strings.ToLower(g[:1]) == g[:1] {
		return "" // a builtin or an unexported type, not a model
	}
	return g
}

func hasRule(binding, rule string) bool {
	for _, part := range strings.Split(binding, ",") {
		if part == rule {
			return true
		}
	}
	return false
}

// constraint turns a binding tag into something readable, so `oneof=SLACK
// WEBHOOK` reaches the page as the list of values it is.
func constraint(binding string) string {
	var out []string
	for _, part := range strings.Split(binding, ",") {
		switch {
		case strings.HasPrefix(part, "oneof="):
			out = append(out, "one of "+strings.Join(strings.Fields(part[6:]), ", "))
		case strings.HasPrefix(part, "min="):
			out = append(out, "minimum "+part[4:])
		case strings.HasPrefix(part, "max="):
			out = append(out, "maximum "+part[4:])
		case strings.HasPrefix(part, "len="):
			out = append(out, "exactly "+part[4:]+" long")
		case part == "email":
			out = append(out, "an email address")
		case part == "url":
			out = append(out, "a URL")
		case part == "uuid":
			out = append(out, "a UUID")
		case part == "hostname":
			out = append(out, "a hostname")
		}
	}
	return strings.Join(out, ", ")
}

func str(e ast.Expr) (string, bool) {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(lit.Value)
	if err != nil {
		return "", false
	}
	return s, true
}

func bare(e ast.Expr) string {
	return strings.TrimPrefix(goType(e), "*")
}

func single[T ast.Expr](exprs []ast.Expr) (T, bool) {
	var zero T
	if len(exprs) != 1 {
		return zero, false
	}
	v, ok := exprs[0].(T)
	return v, ok
}

// clean folds a Go doc comment into one paragraph: a newline inside a Markdown
// table cell ends the row.
func clean(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	// strings.Fields collapses the run of whitespace a blank line leaves
	// behind. Joining lines naively turned every paragraph break into a
	// double space in the middle of a table cell.
	return strings.Join(strings.Fields(s), " ")
}

var statuses = map[string]int{
	"StatusOK": 200, "StatusCreated": 201, "StatusAccepted": 202,
	"StatusNoContent": 204, "StatusBadRequest": 400, "StatusUnauthorized": 401,
	"StatusForbidden": 403, "StatusNotFound": 404, "StatusConflict": 409,
	"StatusGone": 410, "StatusUnprocessableEntity": 422, "StatusTooManyRequests": 429,
	"StatusInternalServerError": 500, "StatusNotImplemented": 501,
	"StatusBadGateway": 502, "StatusServiceUnavailable": 503, "StatusGatewayTimeout": 504,
}

func statusCode(e ast.Expr) (int, bool) {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok {
		return 0, false
	}
	code, ok := statuses[sel.Sel.Name]
	return code, ok
}

// parseArgs reads "-o <out>" and an optional input path, defaulting to stdin.
//
// -o is required rather than defaulting to the input path, because the whole
// point of #50's fix is that the file this writes is never the file another
// pass already wrote.
func parseArgs(args []string) (out, in string) {
	in = "-"
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "-o":
			if i+1 >= len(args) {
				fatal("-o needs a path")
			}
			out = args[i+1]
			i++
		case strings.HasPrefix(args[i], "-o="):
			out = strings.TrimPrefix(args[i], "-o=")
		case strings.HasPrefix(args[i], "-"):
			if args[i] != "-" {
				fatal("unknown flag %q", args[i])
			}
			in = "-"
		default:
			in = args[i]
		}
	}
	if out == "" {
		fatal("usage: schemagen -o <out.json> [in.json]   (input defaults to stdin)")
	}
	return out, in
}

func readInput(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

// writeAtomic writes beside the target and renames over it, so a reader never
// sees a half-written inventory and a crash mid-write leaves the old one.
//
// The same rule agent/install.go follows for a certificate, for the same
// reason: the failure being avoided is not "the write errored", it is "the
// write errored after destroying what was there".
func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op once the rename has succeeded

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	// CreateTemp makes 0600; this file is checked in and read by everything.
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "schemagen: "+format+"\n", args...)
	os.Exit(1)
}
