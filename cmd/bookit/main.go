// Command bookit is the BookIt API server and its admin tools.
//
// Usage:
//
//	bookit                                run the HTTP server
//	bookit create-admin -email E -name N [-password-stdin]
//	                                      create a super admin account
package main

import (
	"fmt"
	"log/slog"
	"os"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		slog.Error("bookit failed", "error", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return runServer()
	}
	switch args[0] {
	case "create-admin":
		return runCreateAdmin(args[1:])
	default:
		return fmt.Errorf("unknown command %q (available: create-admin)", args[0])
	}
}
