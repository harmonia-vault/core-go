package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"runtime"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/harmonia-vault/core-go/localipc"
	"github.com/harmonia-vault/core-go/platform"
)

// importEnvironment 隔离列名与取值，测试只能注入合成提供者。
// 默认实现枚举当前 CLI 进程继承的环境，不读取其它进程、注册表或 shell 文件。
type importEnvironment interface {
	Names() []string
	Lookup(string) (string, bool)
	CaseInsensitive() bool
}
type processImportEnvironment struct{}

func (processImportEnvironment) Names() []string {
	entries := os.Environ()
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if name, _, ok := strings.Cut(entry, "="); ok {
			// 独立复制名称，不让名字切片继续持有含值 entry 的底层字符串。
			names = append(names, strings.Clone(name))
		}
	}
	// os.Environ 本身返回含值的 entry；本函数不输出/缓存值，也不逐项 Lookup。
	clear(entries)
	return names
}
func (processImportEnvironment) Lookup(name string) (string, bool) { return os.LookupEnv(name) }
func (processImportEnvironment) CaseInsensitive() bool             { return runtime.GOOS == "windows" }
func importSource(r commandRuntime) importEnvironment {
	if r.environment != nil {
		return r.environment
	}
	return processImportEnvironment{}
}
func importNameKey(source importEnvironment, name string) string {
	if source.CaseInsensitive() {
		return strings.ToUpper(name)
	}
	return name
}
func importNameIndex(source importEnvironment) (map[string]string, error) {
	names := source.Names()
	if len(names) > 4096 {
		return nil, errors.New("进程环境名称超过扫描上限")
	}
	index := make(map[string]string, len(names))
	for _, name := range names {
		if !platform.ValidName(name) {
			continue
		}
		key := importNameKey(source, name)
		if previous, ok := index[key]; ok && previous != name {
			return nil, errors.New("进程环境名称存在大小写歧义")
		}
		index[key] = name
	}
	return index, nil
}
func selectedImportNames(source importEnvironment, index map[string]string, selected string) ([]string, error) {
	if selected == "" {
		return nil, errors.New("进程环境导入须明确--select")
	}
	if len(selected) > 16*129 {
		return nil, errors.New("选择名称超过导入上限")
	}
	names := strings.Split(selected, ",")
	if len(names) > 16 {
		return nil, errors.New("一次最多选择16个变量")
	}
	seen := map[string]bool{}
	actual := make([]string, 0, len(names))
	for _, name := range names {
		if !platform.ValidName(name) {
			return nil, errors.New("选中进程变量名无效")
		}
		key := importNameKey(source, name)
		if seen[key] {
			return nil, errors.New("不能重复选择同一进程变量")
		}
		canonical, ok := index[key]
		if !ok {
			return nil, errors.New("选中的变量不在当前进程环境中")
		}
		seen[key] = true
		actual = append(actual, canonical)
	}
	sort.Strings(actual)
	return actual, nil
}
func previewProcessImport(source importEnvironment, selected string, out io.Writer) error {
	index, err := importNameIndex(source)
	if err != nil {
		return err
	}
	names := make([]string, 0, len(index))
	if selected != "" {
		names, err = selectedImportNames(source, index, selected)
		if err != nil {
			return err
		}
	} else {
		for _, name := range index {
			names = append(names, name)
		}
		sort.Strings(names)
	}
	return json.NewEncoder(out).Encode(names)
}
func processImportRequest(source importEnvironment, environment, id, selected string) (localipc.Request, error) {
	index, err := importNameIndex(source)
	if err != nil {
		return localipc.Request{}, err
	}
	names, err := selectedImportNames(source, index, selected)
	if err != nil {
		return localipc.Request{}, err
	}
	chosen := make(map[string]string, len(names))
	total := 0
	for _, name := range names {
		value, ok := source.Lookup(name)
		if !ok {
			return localipc.Request{}, errors.New("选中变量已不在当前进程环境中")
		}
		if len(value) > 65536 || !utf8.ValidString(value) || strings.ContainsRune(value, 0) {
			return localipc.Request{}, errors.New("选中进程变量值无效或超过64KiB")
		}
		total += len(value)
		if total > 65536 {
			return localipc.Request{}, errors.New("选中变量值合计超过64KiB")
		}
		chosen[name] = value
	}
	// 只序列化已选值并复用既有显式导入封装；不会输出 JSON、写候选文件或直接改 Engine。
	data, err := json.Marshal(chosen)
	if err != nil {
		return localipc.Request{}, errors.New("选中进程变量无法编码")
	}
	defer clear(data)
	return sharedCLIRequest("import", environment, "", id, false, true, "", strings.Join(names, ","), bytes.NewReader(data))
}
