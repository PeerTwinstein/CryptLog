//go:build cryptlog_image

package main

import (
	"fmt"
	"os"
)

func werkzeug([]string) {
	fmt.Fprintln(os.Stderr, "cryptlog werkzeug läuft nicht im Image der Plattform")
	os.Exit(2)
}
