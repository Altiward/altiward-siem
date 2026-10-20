// rulecheck checks this repository's detections and builds the Sentinel ARM template.
//
//	go run ./tools/rulecheck check [dir]   check the rules, searches and fixtures
//	go run ./tools/rulecheck arm [dir]     print sentinel/azuredeploy.json
//
// It checks each Sentinel rule's keys against the schema Microsoft's Azure-Sentinel
// repository uses, and that every field a rule, hunting query or saved search names is in
// a fixture record it could match: the server's OCSF examples for "altiward" content, the
// forwarder's for "forwarder" content.
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 || len(os.Args) > 3 {
		usage()
	}
	root := "."
	if len(os.Args) == 3 {
		root = os.Args[2]
	}
	switch os.Args[1] {
	case "check":
		problems := check(root)
		for _, p := range problems {
			fmt.Fprintln(os.Stderr, p)
		}
		if len(problems) > 0 {
			fmt.Fprintf(os.Stderr, "%d problems\n", len(problems))
			os.Exit(1)
		}
		fmt.Println("ok")
	case "arm":
		rules, errs := loadRules(root)
		for _, err := range errs {
			fmt.Fprintln(os.Stderr, err)
		}
		if len(errs) > 0 {
			os.Exit(1)
		}
		b, err := buildARM(rules)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Stdout.Write(b)
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: rulecheck check|arm [dir]")
	os.Exit(2)
}
