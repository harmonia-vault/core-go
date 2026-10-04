//go:build windows && harmonia_windows_account_candidate

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/harmonia-vault/core-go/windowsaccount"
	"io"
	"os"
	"unicode/utf16"
	"unicode/utf8"
)

func passwordInput(r io.Reader) ([]uint16, error) {
	b, e := io.ReadAll(io.LimitReader(r, 1025))
	defer clear(b)
	if e != nil || len(b) == 0 || len(b) > 1024 {
		return nil, errors.New("password_input_rejected")
	}
	b = bytes.TrimSuffix(b, []byte{'\n'})
	b = bytes.TrimSuffix(b, []byte{'\r'})
	out := make([]uint16, 0, 257)
	for len(b) > 0 {
		runeValue, n := utf8.DecodeRune(b)
		if runeValue == 0 || runeValue == '\n' || runeValue == '\r' || runeValue == utf8.RuneError && n == 1 {
			clear(out)
			return nil, errors.New("password_input_rejected")
		}
		width := 1
		if runeValue > 0xffff {
			width = 2
		}
		if len(out)+width > 256 {
			clear(out)
			return nil, errors.New("password_input_rejected")
		}
		if runeValue > 0xffff {
			a, z := utf16.EncodeRune(runeValue)
			out = append(out, uint16(a), uint16(z))
		} else {
			out = append(out, uint16(runeValue))
		}
		b = b[n:]
	}
	if len(out) == 0 || len(out) > 256 {
		clear(out)
		return nil, errors.New("password_input_rejected")
	}
	return append(out, 0), nil
}
func run(args []string) error {
	if len(args) == 4 && args[0] == "install" && args[1] == "--plan" && args[3] == "--password-stdin" {
		f, e := os.Open(args[2])
		if e != nil {
			return errors.New("install_plan_unavailable")
		}
		defer f.Close()
		d := json.NewDecoder(io.LimitReader(f, 16385))
		d.DisallowUnknownFields()
		var request windowsaccount.InstallRequest
		if d.Decode(&request) != nil || d.Decode(new(any)) != io.EOF {
			return errors.New("install_plan_rejected")
		}
		password, e := passwordInput(os.Stdin)
		if e != nil {
			return e
		}
		defer clear(password)
		result, e := windowsaccount.Install(request, password)
		_ = json.NewEncoder(os.Stdout).Encode(result)
		return e
	}
	if len(args) != 3 || args[1] != "--config" {
		return errors.New("usage: install --plan <file> --password-stdin | start|stop|remove --config <file>")
	}
	var result windowsaccount.Receipt
	var e error
	switch args[0] {
	case "start":
		result, e = windowsaccount.StartInstalled(args[2])
	case "stop":
		result, e = windowsaccount.StopInstalled(args[2])
	case "remove":
		result, e = windowsaccount.RemoveInstalled(args[2])
	default:
		return errors.New("unknown_install_operation")
	}
	_ = json.NewEncoder(os.Stdout).Encode(result)
	return e
}
func main() {
	if err := run(os.Args[1:]); err != nil {
		_, _ = io.WriteString(os.Stderr, err.Error()+"\n")
		os.Exit(1)
	}
}
