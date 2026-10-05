package windowsservice

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"strings"
	"unicode/utf16"

	"github.com/harmonia-vault/core-go/platform"
)

const maxFrame = 1 << 20

// flatFields 明确拒绝重复键、额外 JSON 与非 object；不让后一个字段覆盖先前检查。
func flatFields(data []byte, limit int) (map[string]json.RawMessage, error) {
	if len(data) == 0 || len(data) > limit {
		return nil, ErrProtocol
	}
	d := json.NewDecoder(bytes.NewReader(data))
	token, e := d.Token()
	if e != nil || token != json.Delim('{') {
		return nil, ErrProtocol
	}
	fields := map[string]json.RawMessage{}
	for d.More() {
		token, e = d.Token()
		if e != nil {
			return nil, ErrProtocol
		}
		key, ok := token.(string)
		if !ok {
			return nil, ErrProtocol
		}
		if _, ok = fields[key]; ok {
			return nil, ErrProtocol
		}
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return nil, ErrProtocol
		}
		fields[key] = value
	}
	token, e = d.Token()
	if e != nil || token != json.Delim('}') {
		return nil, ErrProtocol
	}
	if _, e = d.Token(); e != io.EOF {
		return nil, ErrProtocol
	}
	return fields, nil
}

type request struct {
	Op     string `json:"op"`
	Name   string `json:"name,omitempty"`
	Value  string `json:"value,omitempty"`
	Expand bool   `json:"expand,omitempty"`
}
type response struct {
	Exists bool   `json:"exists"`
	Value  string `json:"value"`
	Expand bool   `json:"expand"`
	Code   string `json:"code"`
}

func decodeRequest(data []byte) (request, error) {
	var r request
	fields, e := flatFields(data, maxFrame)
	if e != nil {
		return r, e
	}
	for k, v := range fields {
		switch k {
		case "op":
			e = json.Unmarshal(v, &r.Op)
		case "name":
			e = json.Unmarshal(v, &r.Name)
		case "value":
			e = json.Unmarshal(v, &r.Value)
		case "expand":
			e = json.Unmarshal(v, &r.Expand)
		default:
			return r, ErrProtocol
		}
		if e != nil || bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return r, ErrProtocol
		}
	}
	if r.Op == "notify" {
		if len(fields) != 1 {
			return r, ErrProtocol
		}
		return r, nil
	}
	if !platform.ValidName(r.Name) {
		return r, ErrProtocol
	}
	switch r.Op {
	case "read", "delete":
		if len(fields) != 2 {
			return r, ErrProtocol
		}
	case "set":
		if len(fields) != 4 || fields["value"] == nil || fields["expand"] == nil || strings.ContainsRune(r.Value, 0) || len(utf16.Encode([]rune(r.Value))) > 32767 {
			return r, ErrProtocol
		}
	default:
		return r, ErrProtocol
	}
	return r, nil
}
func readFrame(reader io.Reader) ([]byte, error) {
	var header [4]byte
	if _, e := io.ReadFull(reader, header[:]); e != nil {
		return nil, e
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > maxFrame {
		return nil, ErrProtocol
	}
	data := make([]byte, size)
	_, e := io.ReadFull(reader, data)
	return data, e
}
func writeFrame(writer io.Writer, data []byte) error {
	if len(data) == 0 || len(data) > maxFrame {
		return ErrProtocol
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(data)))
	for _, b := range [][]byte{header[:], data} {
		for len(b) > 0 {
			n, e := writer.Write(b)
			if e != nil {
				return e
			}
			if n <= 0 || n > len(b) {
				return io.ErrShortWrite
			}
			b = b[n:]
		}
	}
	return nil
}
func execute(store platform.UserEnvironmentStore, r request) response {
	var out response
	var e error
	switch r.Op {
	case "read":
		var value platform.RegistryValue
		value, out.Exists, e = store.Read(r.Name)
		out.Value = value.Value
		out.Expand = value.Expand
	case "set":
		e = store.Set(r.Name, platform.RegistryValue{Value: r.Value, Expand: r.Expand})
	case "delete":
		e = store.Delete(r.Name)
	case "notify":
		e = store.Notify()
	default:
		e = ErrProtocol
	}
	if e != nil {
		out = response{Code: "operation_rejected"}
	}
	return out
}
