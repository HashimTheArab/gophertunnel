package service

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestServiceHTTPUsesSharedHelper(t *testing.T) {
	for _, root := range []string{".", "../realms"} {
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				return err
			}
			// Only the shared implementation may call the auth retry sender.
			for _, pos := range directHTTP(file, filepath.ToSlash(path) == "internal/request.go") {
				t.Errorf("%s: use the shared service request helper", fset.Position(pos))
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

// directHTTP finds direct HTTP sends, including method values and aliased imports.
// Unknown Do receivers are rejected; the only exception is a declared sync.Once.
func directHTTP(file *ast.File, shared bool) []token.Pos {
	imports := map[string]string{}
	var violations []token.Pos
	for _, imp := range file.Imports {
		path, _ := strconv.Unquote(imp.Path.Value)
		name := filepath.Base(path)
		if imp.Name != nil {
			name = imp.Name.Name
		}
		imports[name] = path
		if name == "." && (path == "net/http" || strings.HasSuffix(path, "/auth/authclient")) {
			violations = append(violations, imp.Pos())
		}
	}
	ast.Inspect(file, func(node ast.Node) bool {
		sel, ok := node.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, packageSelector := sel.X.(*ast.Ident)
		jsonHelper := packageSelector && pkg.Obj == nil && imports[pkg.Name] == "github.com/sandertv/gophertunnel/minecraft/service/internal/request"
		if sel.Sel.Name == "Do" && !jsonHelper && !syncOnceType(declaredType(file, sel.X), imports) {
			violations = append(violations, sel.Pos())
		}
		if pkg, ok := sel.X.(*ast.Ident); ok {
			switch imports[pkg.Name] {
			case "net/http":
				switch sel.Sel.Name {
				case "Get", "Post", "PostForm", "Head":
					violations = append(violations, sel.Pos())
				}
			case "github.com/sandertv/gophertunnel/minecraft/auth/authclient":
				if sel.Sel.Name == "SendRequestWithRetries" && !shared {
					violations = append(violations, sel.Pos())
				}
			}
		}
		return true
	})
	return violations
}

// declaredType resolves local variables and fields only far enough to recognise sync.Once.
func declaredType(file *ast.File, expr ast.Expr) ast.Expr {
	switch expr := expr.(type) {
	case *ast.Ident:
		if expr.Obj != nil {
			switch decl := expr.Obj.Decl.(type) {
			case *ast.ValueSpec:
				return decl.Type
			case *ast.Field:
				return decl.Type
			}
		}
	case *ast.SelectorExpr:
		typ := declaredType(file, expr.X)
		if ptr, ok := typ.(*ast.StarExpr); ok {
			typ = ptr.X
		}
		if name, ok := typ.(*ast.Ident); ok {
			if obj := file.Scope.Lookup(name.Name); obj != nil {
				if decl, ok := obj.Decl.(*ast.TypeSpec); ok {
					if fields, ok := decl.Type.(*ast.StructType); ok {
						for _, field := range fields.Fields.List {
							for _, name := range field.Names {
								if name.Name == expr.Sel.Name {
									return field.Type
								}
							}
						}
					}
				}
			}
		}
	}
	return nil
}

// syncOnceType identifies sync.Once using the file's import aliases.
func syncOnceType(expr ast.Expr, imports map[string]string) bool {
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Once" {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && imports[pkg.Name] == "sync"
}

func TestDirectHTTPGuard(t *testing.T) {
	for _, test := range []struct {
		source string
		shared bool
		want   int
	}{
		{source: `package p; func f() { client.Do(req) }`, want: 1},
		{source: `package p; import h "net/http"; var send = h.Get`, want: 1},
		{source: `package p; import "net/http"; var send = (*http.Client).Do`, want: 1},
		{source: `package p; import "net/http"; func f() { http.DefaultClient.Do(req) }`, want: 1},
		{source: `package p; import a "github.com/sandertv/gophertunnel/minecraft/auth/authclient"; var send = a.SendRequestWithRetries`, want: 1},
		{source: `package p; import a "github.com/sandertv/gophertunnel/minecraft/auth/authclient"; var send = a.SendRequestWithRetries`, shared: true},
		{source: `package p; import "sync"; func f() { var once sync.Once; once.Do(f) }`},
		{source: `package p; import r "github.com/sandertv/gophertunnel/minecraft/service/internal/request"; func f() { r.Do(ctx, client) }`},
		{source: `package p; import "sync"; type C struct { once sync.Once }; func (c *C) f() { c.once.Do(f) }`},
		{source: `package p; import "net/http"; type C struct { once *http.Client }; func (c *C) f() { c.once.Do(req) }`, want: 1},
	} {
		file, err := parser.ParseFile(token.NewFileSet(), "guard.go", test.source, 0)
		if err != nil {
			t.Fatal(err)
		}
		if got := len(directHTTP(file, test.shared)); got != test.want {
			t.Errorf("%s: violations = %d, want %d", test.source, got, test.want)
		}
	}
}
