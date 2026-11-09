//go:build !windows

package oberflaeche

func dateiWaehlen(string) (string, bool) { return "", false }

func ordnerWaehlen(string) (string, bool) { return "", false }
