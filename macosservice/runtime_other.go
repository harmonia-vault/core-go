//go:build !darwin

package macosservice

import "errors"

func New(Target) (*Manager, error) {
	return nil, errors.New("此安装入口只支持 macOS，未执行任何操作")
}
