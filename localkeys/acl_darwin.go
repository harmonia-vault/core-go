//go:build darwin

package localkeys

import (
	"encoding/binary"
	"runtime"
	"syscall"
	"unsafe"
)

// macOS 没有在 x/sys 导出 fgetattrlist；以下绑定使用本机官方 SDK sys/attr.h 与 sys/kauth.h 的 ABI。
// 只读 ACL 是否存在；不创建、修改或尝试解释允许权限。任何非空 ACL 均拒绝。
func checkExtendedACL(fd int, directory bool) error {
	type attributeList struct {
		Count     uint16
		Reserved  uint16
		Common    uint32
		Volume    uint32
		Directory uint32
		File      uint32
		Fork      uint32
	}
	list := attributeList{Count: 5, Common: 0x00400000}
	buffer := make([]byte, 8192)
	_, _, errno := syscall.Syscall6(228, uintptr(fd), uintptr(unsafe.Pointer(&list)), uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)), 0, 0)
	runtime.KeepAlive(list)
	runtime.KeepAlive(buffer)
	if errno != 0 {
		return ErrPermission
	}
	length := int(binary.LittleEndian.Uint32(buffer[:4]))
	if length < 12 || length > len(buffer) {
		return ErrPermission
	}
	offset := int(int32(binary.LittleEndian.Uint32(buffer[4:8]))) + 4
	size := int(binary.LittleEndian.Uint32(buffer[8:12]))
	if size == 0 {
		return nil
	}
	if offset < 12 || size < 44 || offset+size > length {
		return ErrPermission
	}
	count := binary.LittleEndian.Uint32(buffer[offset+36 : offset+40])
	if count == 0 || count == 0xffffffff {
		return nil
	}
	return ErrPermission
}
