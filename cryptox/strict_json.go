package cryptox

import (
	"bytes"
	"encoding/json"
	"io"
	"unicode/utf8"
)

const MaxStrictJSONDepth = 64
const maxStrictJSONTokens = 250000

// ValidateStrictJSON 在 typed 解码之前拒绝重复对象键、无效 UTF-8、超深结构
// 和额外 JSON。字段名按 JSON 转义解码后比较；输入/解析工作均有固定上限。
// 它不取代 typed schema 的 DisallowUnknownFields 或密码学语义检查。
func ValidateStrictJSON(data []byte, maximum int) error {
	if maximum <= 0 || len(data) == 0 || len(data) > maximum || !utf8.Valid(data) {
		return ErrInvalidWire
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	tokens := 0
	var value func(int) error
	token := func() (json.Token, error) {
		tokens++
		if tokens > maxStrictJSONTokens {
			return nil, ErrInvalidWire
		}
		return d.Token()
	}
	value = func(depth int) error {
		if depth > MaxStrictJSONDepth {
			return ErrInvalidWire
		}
		t, e := token()
		if e != nil {
			return ErrInvalidWire
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				key, e := token()
				if e != nil {
					return ErrInvalidWire
				}
				name, ok := key.(string)
				if !ok || seen[name] {
					return ErrInvalidWire
				}
				seen[name] = true
				if e = value(depth + 1); e != nil {
					return e
				}
			}
			end, e := token()
			if e != nil || end != json.Delim('}') {
				return ErrInvalidWire
			}
			return nil
		case '[':
			for d.More() {
				if e = value(depth + 1); e != nil {
					return e
				}
			}
			end, e := token()
			if e != nil || end != json.Delim(']') {
				return ErrInvalidWire
			}
			return nil
		default:
			return ErrInvalidWire
		}
	}
	if e := value(1); e != nil {
		return e
	}
	if _, e := d.Token(); e != io.EOF {
		return ErrInvalidWire
	}
	return nil
}
