// Command sharingan is a recon/scan orchestrator with a built-in
// WAF/bot-detection stealth engine. See README.md for the full command
// reference.
package main

import (
	"os"

	"github.com/Mohamed-Newish/sharingan-go/cmd"
)

func main() {
	os.Exit(cmd.Run(os.Args))
}
