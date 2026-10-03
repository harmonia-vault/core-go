//go:build darwin

package macosservice

import (
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"testing"
)

// 仅普通用户自己临时父FD，不执行root安装或查询任何launchctl数据库。
func TestV6DarwinExclusiveCreationPreservesExactInodeAndNeverReplaces(t *testing.T) {
	for _, kind := range []string{"original", "different-final", "different-stage"} {
		t.Run(kind, func(t *testing.T) {
			d := t.TempDir()
			parent, e := unix.Open(d, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if e != nil {
				t.Fatal(e)
			}
			defer unix.Close(parent)
			b := []byte("synthetic-public-source")
			if e = os.WriteFile(d+"/stage", b, 0600); e != nil {
				t.Fatal(e)
			}
			n, e := inspectAt(parent, "stage")
			if e != nil {
				t.Fatal(e)
			}
			pn, e := statFD(parent)
			if e != nil {
				t.Fatal(e)
			}
			x := creation{Stage: "stage", Node: n, Parent: pn, FinalParent: pn, Hash: digest(b)}
			switch kind {
			case "different-final":
				if e = os.WriteFile(d+"/final", []byte("unrelated"), 0600); e != nil {
					t.Fatal(e)
				}
			case "different-stage":
				if e = os.Rename(d+"/stage", d+"/old-stage"); e != nil {
					t.Fatal(e)
				}
				if e = os.WriteFile(d+"/stage", b, 0600); e != nil {
					t.Fatal(e)
				}
			}
			f := &darwinFS{}
			e = f.commitCreationAt(parent, parent, "final", x)
			if kind != "original" {
				if !errors.Is(e, ErrUnknown) {
					t.Fatal("身份不明仍rename", e)
				}
				if kind == "different-final" {
					got, _ := os.ReadFile(d + "/final")
					if string(got) != "unrelated" {
						t.Fatal("覆盖已有文件")
					}
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			got, e := inspectAt(parent, "final")
			if e != nil || !equalNode(got, n) {
				t.Fatal("没有发布原inode", got, e)
			}
			if _, e = inspectAt(parent, "stage"); !errors.Is(e, os.ErrNotExist) {
				t.Fatal("stage仍存在", e)
			}
			if e = f.commitCreationAt(parent, parent, "final", x); e != nil {
				t.Fatal("rename结果不明后不能核同父并同步", e)
			}
		})
	}
}

func TestV7CreatedChildrenBoundedOnActualOwnedTemporaryFD(t *testing.T) {
	for _, count := range []int{128, 129} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			parentPath := t.TempDir()
			path := parentPath + "/state"
			if e := os.Mkdir(path, 0700); e != nil {
				t.Fatal(e)
			}
			for i := 0; i < count; i++ {
				if e := os.WriteFile(fmt.Sprintf("%s/item-%03d", path, i), nil, 0600); e != nil {
					t.Fatal(e)
				}
			}
			parent, e := unix.Open(parentPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if e != nil {
				t.Fatal(e)
			}
			defer unix.Close(parent)
			n, e := inspectAt(parent, "state")
			if e != nil {
				t.Fatal(e)
			}
			xs, e := childrenCreatedAt(parent, "state", n)
			if count == 128 {
				if e != nil || len(xs) != 128 {
					t.Fatal("合法有限集合失败", len(xs), e)
				}
			} else if !errors.Is(e, ErrUnknown) || len(xs) != 0 {
				t.Fatal("超限集合仍无界枚举成功", len(xs), e)
			}
			original, e := inspectAt(parent, "state")
			if e != nil || !equalNode(original, n) {
				t.Fatal("读取修改原目录", e)
			}
		})
	}
}
