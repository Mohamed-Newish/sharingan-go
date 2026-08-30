// Command sharingan is a recon/scan orchestrator with a built-in
// WAF/bot-detection stealth engine — the Go successor to
// https://github.com/Mohamed-Newish/Sharingan's recon.sh + scanners.sh.
// See README.md for the full command reference.
package main

import (
	"os"

	"github.com/Mohamed-Newish/sharingan-go/cmd"
)

func main() {
	os.Exit(cmd.Run(os.Args))
}
