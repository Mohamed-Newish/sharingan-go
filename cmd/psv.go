// psv.go implements `sharingan psv`: passive recon only. No source
// reachable from here may open a connection to the target's own
// infrastructure — only third-party services (crt.sh, passive DNS,
// web archives) get touched.
package cmd

import (
	"flag"
	"fmt"
	"os"

	"github.com/Mohamed-Newish/sharingan-go/internal/output"
	"github.com/Mohamed-Newish/sharingan-go/internal/passive"
)

func runPsv(args []string) int {
	fs := flag.NewFlagSet("psv", flag.ExitOnError)
	g := &Global{}
	registerGlobal(fs, g)
	sources := fs.String("sources", "crtsh,subfinder,wayback,gau",
		"comma list of passive sources: crtsh,subfinder,amass-passive,assetfinder,securitytrails,censys,shodan,github,wayback,gau,otx")
	fs.Parse(args)

	targets, err := g.Targets()
	if err != nil {
		fmt.Fprintln(os.Stderr, "sharingan psv:", err)
		return 2
	}

	for _, t := range targets {
		lay, err := output.New(g.Out, t)
		if err != nil {
			fmt.Fprintln(os.Stderr, "sharingan psv:", err)
			return 1
		}
		if err := passive.Run(t, lay, *sources, g.DryRun, g.Verbose); err != nil {
			fmt.Fprintf(os.Stderr, "sharingan psv: %s: %v\n", t, err)
		}
	}
	return 0
}
