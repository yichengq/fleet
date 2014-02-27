package main

import (
	"path"

	"github.com/coreos/fleet/third_party/github.com/codegangsta/cli"

	"github.com/coreos/fleet/signing"
)

func newDestroyUnitCommand() cli.Command {
	return cli.Command{
		Name:	"destroy",
		Usage:	"Destroy one or more units in the cluster",
		Description: `Completely remove a running or submitted unit from the cluster.

Instructs systemd on the host machine to stop the unit, deferring to systemd
completely for any custom stop directives (i.e. ExecStop option in the unit
file).

Destroyed units are impossible to start unless re-submitted.`,
		Action:	destroyUnitsAction,
	}
}

func destroyUnitsAction(c *cli.Context) {
	r := getRegistry(c)
	s := signing.New(r)

	for _, v := range c.Args() {
		name := path.Base(v)
		r.StopJob(name)
		r.DestroyPayload(name)
		s.DeregisterPayload(name)
	}
}
