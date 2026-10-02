package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/harmonia-vault/core-go/localipc"
	"github.com/harmonia-vault/core-go/localstate"
)

func sharedCLIRequest(command, environment, name, id string, valueStdin, importStdin bool, from, selected string, input io.Reader) (localipc.Request, error) {
	if id == "" {
		if command == "write-retry" {
			return localipc.Request{}, errors.New("write-retry需要原request-id")
		}
		var err error
		id, err = randomLocalID("write-")
		if err != nil {
			return localipc.Request{}, err
		}
	}
	request := localipc.Request{Command: command, EnvironmentID: environment, Name: name, RequestID: id}
	switch command {
	case "put":
		if !valueStdin || importStdin || input == nil || from != "" || selected != "" {
			return request, errors.New("put须明确--value-stdin，不接收argv值或候选文件")
		}
		value, err := readSharedInput(input)
		if err != nil {
			return request, err
		}
		request.Value = &value
	case "delete":
		if valueStdin || importStdin || from != "" || selected != "" {
			return request, errors.New("delete不接收变量值")
		}
	case "import":
		if valueStdin || !importStdin || input == nil || from != "" || selected == "" || name != "" {
			return request, errors.New("import须明确--import-stdin和--select，只发送选中变量")
		}
		data, err := io.ReadAll(io.LimitReader(input, (1<<20)+1))
		if err != nil || len(data) > 1<<20 {
			return request, errors.New("候选JSON无效或超过1MiB")
		}
		defer clear(data)
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		var candidates map[string]string
		var extra any
		if decoder.Decode(&candidates) != nil || decoder.Decode(&extra) != io.EOF {
			return request, errors.New("候选变量JSON无效")
		}
		chosen, err := localstate.SelectImport(candidates, strings.Split(selected, ","))
		if err != nil {
			return request, errors.New("选中变量无效")
		}
		request.Selected = chosen
	case "write-retry":
		if valueStdin || importStdin || from != "" || selected != "" || environment != "" || name != "" {
			return request, errors.New("write-retry只接受原request-id，不重新输入值或授权")
		}
	default:
		return request, errors.New("无效共享写命令")
	}
	return request, nil
}

func readSharedInput(input io.Reader) (string, error) {
	if input == nil {
		return "", errors.New("缺少明确标准输入")
	}
	data, err := io.ReadAll(io.LimitReader(input, 65537))
	if err != nil || len(data) > 65536 || !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 {
		clear(data)
		return "", errors.New("标准输入值无效或超过64KiB")
	}
	value := string(data)
	clear(data)
	return value, nil
}
