//go:build !cryptlog_image

package main

import (
	"cryptlog/oberflaeche"
)

func werkzeug(args []string) {
	if len(args) > 3 {
		usage()
	}
	var pfad string
	if len(args) == 3 {
		pfad = args[2]
	}
	oberflaeche.Start(pfad)
}
