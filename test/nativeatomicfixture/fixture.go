// Package nativeatomicfixture 只供独立 JNI 验收 AAR。正常生产 bind 命令不包含此包。
package nativeatomicfixture

import "github.com/harmonia-vault/core-go/mobilebridge"

// CheckAndCAS 在Go外部代理上执行真实Check/CAS/Check；不会生成云请求或设备信任。
func CheckAndCAS(store mobilebridge.AtomicSealedStateStore, expected, next []byte) error {
	if err := store.CheckSealed(expected); err != nil {
		return err
	}
	if err := store.CompareAndSwapSealed(expected, next); err != nil {
		return err
	}
	return store.CheckSealed(next)
}

// OpenTypedAndLogout 使用真实typed opener，软件临时Device仅存进程，关闭时擦缓冲。
// 合成未入网状态退出不发HTTP；没有Dart/原始材料/任意签名接口。
func OpenTypedAndLogout(namespace string, store mobilebridge.AtomicSealedStateStore) error {
	d, err := mobilebridge.NewDevice()
	if err != nil {
		return err
	}
	defer d.Close()
	w, err := d.OpenAtomicWorkflow("https://synthetic.example.invalid", namespace, nil, nil, store)
	if err != nil {
		return err
	}
	defer w.Close()
	_, err = w.Execute(`{"version":1,"operation":"logout","endpoint":"https://synthetic.example.invalid"}`)
	return err
}
