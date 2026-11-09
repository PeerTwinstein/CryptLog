// Befehl cryptlog startet den Schreibprozess oder das Fenster des Empfängers.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"cryptlog/schreiben"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "schreiben":
		if len(os.Args) != 3 {
			usage()
		}
		dienst, err := schreiben.OeffnenDienst(os.Args[2])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		if err := dienst.Dienen(ctx); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "werkzeug":
		werkzeug(os.Args)
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "Aufruf: cryptlog schreiben <datei>")
	fmt.Fprintln(os.Stderr, "        cryptlog werkzeug [verbindung]")
	os.Exit(2)
}
