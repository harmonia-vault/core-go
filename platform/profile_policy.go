package platform

import "strings"

// 只接受本机普通 DOS 绝对路径；拒绝 UNC、设备命名空间、ADS 和含糊的尾点/空格。
// 不用进程环境扩展路径，也不允许调用方指定 hive 文件。
func profileLocalPath(value string) bool {
	if len(value) < 4 || len(value) > 240 || value[1] != ':' || value[2] != '\\' ||
		!((value[0] >= 'A' && value[0] <= 'Z') || (value[0] >= 'a' && value[0] <= 'z')) ||
		strings.ContainsAny(value[3:], "/:\x00\r\n\"<>|?*%") {
		return false
	}
	for _, part := range strings.Split(value[3:], `\`) {
		if part == "" || part == "." || part == ".." || strings.HasSuffix(part, ".") || strings.HasSuffix(part, " ") {
			return false
		}
		base := strings.ToUpper(strings.SplitN(part, ".", 2)[0])
		if base == "CON" || base == "PRN" || base == "AUX" || base == "NUL" ||
			(len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && base[3] >= '1' && base[3] <= '9') {
			return false
		}
	}
	return true
}
