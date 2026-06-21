package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
)

type GoFunction struct {
	Name string
	Code string
}

func ExtractFunctions(filepath string) ([]GoFunction, error) {
	src, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}

	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, filepath, src, parser.ParseComments)
	if err != nil {
		return nil, err
	}

	var funcs []GoFunction
	for _, decl := range node.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok {
			code := src[fn.Pos()-1 : fn.End()-1]
			funcs = append(funcs, GoFunction{
				Name: fn.Name.Name,
				Code: string(code),
			})
		}
	}
	return funcs, nil
}
