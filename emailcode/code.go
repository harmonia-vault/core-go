// Package emailcode validates the shared registration/reset mail-code format.
package emailcode

import "strings"

// Normalize accepts exactly eight ASCII symbols with both a letter and a digit.
func Normalize(value string) (string, bool) {
	if len(value) != 8 {
		return "", false
	}
	for i := range len(value) {
		if value[i] >= 128 {
			return "", false
		}
	}
	code := strings.ToUpper(value)
	letter, digit := false, false
	for i := range len(code) {
		if !strings.ContainsRune("23456789ABCDEFGHJKLMNPQRSTUVWXYZ", rune(code[i])) {
			return "", false
		}
		if code[i] >= '2' && code[i] <= '9' {
			digit = true
		} else {
			letter = true
		}
	}
	return code, letter && digit
}
