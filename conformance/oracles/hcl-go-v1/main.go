// Command hcl-go-differential is the pinned Go oracle driver for the
// Consema HCL differential gate (RFC 0014 §12, implementation plan §3.4,
// §6.3).
//
// The driver reports parse acceptance only. Document fixtures are parsed
// with hclparse.ParseHCL (which dispatches to hclsyntax.ParseConfig);
// expression fixtures are parsed with hclsyntax.ParseExpression. cty
// evaluation is never invoked, and no value is ever produced or compared:
// the differential contract compares the Go parser's parse outcome with the
// Consema Profile's Complete/Recovered outcome and nothing else.
//
// Output is ASCII TSV on stdout:
//
//	input-sha256<TAB><lowercase hex SHA-256 of the fixture bytes>
//	outcome<TAB>accept|reject
//
// A rejected fixture prints the first diagnostic's summary on stderr for
// human inspection only; it is never compared by the wrapper.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

func main() {
	if len(os.Args) >= 2 && os.Args[1] == "--runtime" {
		printRuntime()
		return
	}
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: hcl-go-differential --document <file> | --expression <file>")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "--document":
		runDocument(os.Args[2])
	case "--expression":
		runExpression(os.Args[2])
	default:
		fmt.Fprintln(os.Stderr, "unknown mode:", os.Args[1])
		os.Exit(2)
	}
}

// printRuntime emits the pinned runtime facts consumed by the wrapper's
// runtime verification (manifest.runtime).
func printRuntime() {
	fmt.Printf("go.version\t%s\n", runtime.Version())
	fmt.Printf("go.os\t%s\n", runtime.GOOS)
	fmt.Printf("go.arch\t%s\n", runtime.GOARCH)
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, module := range info.Deps {
			if module.Path == "github.com/hashicorp/hcl/v2" {
				fmt.Printf("hcl.module\t%s\n", module.Version)
				if module.Replace != nil {
					fmt.Printf("hcl.replaced\t%s@%s\n", module.Replace.Path, module.Replace.Version)
				}
			}
		}
	}
}

// runDocument parses one document fixture with the pinned hclparse.ParseHCL
// entry (RFC 0014 §12) and reports parse acceptance only.
func runDocument(path string) {
	source, err := os.ReadFile(path)
	if err != nil {
		fatal(err)
	}
	emitDigest(source)
	parser := hclparse.NewParser()
	_, diagnostics := parser.ParseHCL(source, path)
	emitOutcome(diagnostics)
}

// runExpression parses one expression fixture with hclsyntax.ParseExpression
// (RFC 0014 §12) and reports parse acceptance only.
func runExpression(path string) {
	source, err := os.ReadFile(path)
	if err != nil {
		fatal(err)
	}
	emitDigest(source)
	_, diagnostics := hclsyntax.ParseExpression(source, path, hcl.InitialPos)
	emitOutcome(diagnostics)
}

// emitDigest prints the fixture's SHA-256, the input pin of the manifest.
func emitDigest(source []byte) {
	sum := sha256.Sum256(source)
	fmt.Printf("input-sha256\t%s\n", hex.EncodeToString(sum[:]))
}

// emitOutcome prints accept/reject; the first diagnostic is echoed to stderr
// for human inspection only and is never compared.
func emitOutcome(diagnostics hcl.Diagnostics) {
	if diagnostics.HasErrors() {
		fmt.Println("outcome\treject")
		for _, diagnostic := range diagnostics {
			if diagnostic.Severity == hcl.DiagError {
				fmt.Fprintln(os.Stderr, "diagnostic", diagnostic.Summary)
				break
			}
		}
		return
	}
	fmt.Println("outcome\taccept")
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "fatal:", err)
	os.Exit(1)
}
