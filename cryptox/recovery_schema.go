package cryptox

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
)

// 新恢复 DTO 必须显式携带每个字段。空字符串不等于缺字段或 null，
// 只有过渡顶层 issuerEvidence/legacyState 允许规范 null。
func validateRecoveryJSONShape(data []byte, t reflect.Type, nullable map[string]bool) error {
	if err := ValidateStrictJSON(data, MaxRecoveryAuthorityBytes); err != nil {
		return err
	}
	return recoveryJSONShape(data, t, "$", nullable)
}
func recoveryJSONShape(data []byte, t reflect.Type, path string, nullable map[string]bool) error {
	data = bytes.TrimSpace(data)
	if bytes.Equal(data, []byte("null")) {
		if nullable[path] && t.Kind() == reflect.Pointer {
			return nil
		}
		return ErrInvalidWire
	}
	if t.Kind() == reflect.Pointer {
		return recoveryJSONShape(data, t.Elem(), path, nullable)
	}
	switch t.Kind() {
	case reflect.Struct:
		var object map[string]json.RawMessage
		if len(data) == 0 || data[0] != '{' || json.Unmarshal(data, &object) != nil {
			return ErrInvalidWire
		}
		allowed := make(map[string]bool, t.NumField())
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if f.PkgPath != "" {
				continue
			}
			tag := strings.Split(f.Tag.Get("json"), ",")
			if tag[0] == "-" {
				continue
			}
			name := tag[0]
			if name == "" {
				name = f.Name
			}
			allowed[name] = true
			raw, ok := object[name]
			optional := false
			for _, v := range tag[1:] {
				optional = optional || v == "omitempty"
			}
			if !ok {
				if optional {
					continue
				}
				return ErrInvalidWire
			}
			if err := recoveryJSONShape(raw, f.Type, path+"."+name, nullable); err != nil {
				return err
			}
		}
		for name := range object {
			if !allowed[name] {
				return ErrInvalidWire
			}
		}
	case reflect.Slice, reflect.Array:
		var items []json.RawMessage
		if len(data) == 0 || data[0] != '[' || json.Unmarshal(data, &items) != nil {
			return ErrInvalidWire
		}
		for _, raw := range items {
			if err := recoveryJSONShape(raw, t.Elem(), path+"[]", nullable); err != nil {
				return err
			}
		}
	case reflect.String:
		var value string
		if json.Unmarshal(data, &value) != nil {
			return ErrInvalidWire
		}
	case reflect.Uint64:
		var value uint64
		if json.Unmarshal(data, &value) != nil {
			return ErrInvalidWire
		}
	default:
		return ErrInvalidWire
	}
	return nil
}
