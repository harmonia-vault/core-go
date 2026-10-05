//go:build windows

package main

import (
	"golang.org/x/sys/windows"
	"testing"
	"unsafe"
)

func TestBatchRightUnicodeLength(t *testing.T) {
	for _, c := range []struct {
		name            string
		length, maximum uint16
	}{{"SeBatchLogonRight", 34, 36}, {"读🚀", 6, 8}} {
		right, units, e := encodedRightName(c.name)
		if e != nil {
			t.Fatal(e)
		}
		if right.Length != c.length || right.Maximum != c.maximum {
			t.Fatalf("byte lengths: %d/%d", right.Length, right.Maximum)
		}
		if right.Buffer != &units[0] || units[len(units)-1] != 0 {
			t.Fatal("wrong backing/null terminator")
		}
		// 模拟标准 UNICODE_STRING 消费者按 Length 解码；旧32bytes会截断固定权限名。
		if got := windows.UTF16ToString(unsafe.Slice(right.Buffer, int(right.Length)/2)); got != c.name {
			t.Fatalf("truncated name: %q", got)
		}
	}
	for _, name := range []string{"", "SeBatch\x00LogonRight"} {
		if _, _, e := encodedRightName(name); e == nil {
			t.Fatal("invalid null/empty name accepted")
		}
	}
}
