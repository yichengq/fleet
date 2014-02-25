package main

import (
	"fmt"
	"path"
	"syscall"

	"github.com/coreos/fleet/third_party/github.com/codegangsta/cli"

	"github.com/coreos/fleet/signing"
)

func newCatUnitCommand() cli.Command {
	return cli.Command{
		Name:	"cat",
		Usage:	"Output the contents of a submitted unit",
		Description: `Outputs the unit file that is currently loaded in the cluster. Useful to verify
the correct version of a unit is running.`,
		Flags:	[]cli.Flag{
			cli.StringFlag{"verify", "yes", "Verify unit file (`yes` or `no`)"},
		},
		Action:	printUnitAction,
	}
}

func printUnitAction(c *cli.Context) {
	r := getRegistry(c)
	s := signing.New(r)

	verify := c.String("verify") == "yes"
	if verify {
		s.SetVerifyBySSHAgent()
	}

	if len(c.Args()) != 1 {
		fmt.Println("One unit file must be provided.")
		syscall.Exit(1)
	}

	name := path.Base(c.Args()[0])
	payload := r.GetPayload(name)

	if payload == nil {
		fmt.Println("Job not found.")
		syscall.Exit(1)
	}

	if verify {
		ok, err := s.VerifyPayload(payload)
		if !ok || err != nil {
			fmt.Printf("Check of payload %s failed: %v\n", payload.Name, err)
			return
		}
	}

	fmt.Print(payload.Unit.String())
}
