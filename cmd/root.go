// Package cmd implements sharingan's two subcommands, psv and act, and
// the flags shared between them.
package cmd

import (
	"flag"
	"fmt"
	"os"

	"github.com/Mohamed-Newish/sharingan-go/internal/scope"
)

const usage = `sharingan — recon/scan orchestrator with a built-in stealth engine

Usage:
  sharingan psv [flags]   passive recon only — zero packets to the target
  sharingan act [flags]   active recon/scan — touches the target, stealth engine on

Run 'sharingan psv -h' or 'sharingan act -h' for mode-specific flags.
`

// Global holds the flags shared by both psv and act.
type Global struct {
	Target  string
	List    string
	Out     string
	Config  string
	Only    string
	Skip    string
	Resume  bool
	DryRun  bool
	Verbose bool
}

func registerGlobal(fs *flag.FlagSet, g *Global) {
	fs.StringVar(&g.Target, "t", "", "single target domain, e.g. example.com")
	fs.StringVar(&g.Target, "target", "", "single target domain, e.g. example.com")
	fs.StringVar(&g.List, "l", "", "scope file, one target per line (wildcards ok)")
	fs.StringVar(&g.List, "list", "", "scope file, one target per line (wildcards ok)")
	fs.StringVar(&g.Out, "o", "targets", "output root directory")
	fs.StringVar(&g.Out, "out", "targets", "output root directory")
	fs.StringVar(&g.Config, "c", "", "config file (API keys, custom profiles)")
	fs.StringVar(&g.Config, "config", "", "config file (API keys, custom profiles)")
	fs.StringVar(&g.Only, "only", "", "comma list: run just these phases")
	fs.StringVar(&g.Skip, "skip", "", "comma list: skip these phases")
	fs.BoolVar(&g.Resume, "resume", false, "skip phases whose output file is already non-empty")
	fs.BoolVar(&g.DryRun, "dry-run", false, "print what would run/request, send nothing")
	fs.BoolVar(&g.Verbose, "v", false, "verbose logging")
}

// Targets resolves -t/-l into the list of targets to run against.
func (g *Global) Targets() ([]string, error) {
	if g.Target == "" && g.List == "" {
		return nil, fmt.Errorf("need -t <target> or -l <scope file>")
	}
	if g.Target != "" {
		return []string{g.Target}, nil
	}
	l, err := scope.Load(g.List)
	if err != nil {
		return nil, err
	}
	return l.Roots(), nil
}

// Run dispatches argv[1] (psv|act) to its subcommand.
func Run(argv []string) int {
	if len(argv) < 2 {
		fmt.Fprint(os.Stderr, usage)
		return 2
	}
	switch argv[1] {
	case "psv":
		return runPsv(argv[2:])
	case "act":
		return runAct(argv[2:])
	case "-h", "--help", "help":
		fmt.Print(usage)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown mode %q\n\n%s", argv[1], usage)
		return 2
	}
}
