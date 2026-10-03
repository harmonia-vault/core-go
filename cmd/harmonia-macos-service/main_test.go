package main

import "testing"

func TestMalformedInputsNeverReachInstaller(t *testing.T) {
	for _, args := range [][]string{nil, {"upgrade"}, {"install", "--user", "synthetic", "--uid", "0501", "--gid", "20"}, {"install", "--uid", "501", "--gid", "-1"}, {"stop", "--uid", "501", "--gid", "20", "--binary", "/approved/program"}, {"install", "--uid", "501", "--gid", "20", "extra"}} {
		if e := run(args); e == nil {
			t.Fatal("错误参数被接受", args)
		}
	}
}
