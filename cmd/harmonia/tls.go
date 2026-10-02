package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"os"
	"time"
)

// 用户显式选择自托管CA；不关闭链、主机名或证书期限验证。
func clientWithCA(path string) (*http.Client, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("无法读取明确指定的CA文件")
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil || len(data) == 0 || len(data) > 1<<20 {
		return nil, errors.New("CA文件无效或超出1MiB")
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	rest := data
	count := 0
	for len(bytes.TrimSpace(rest)) > 0 {
		if !bytes.HasPrefix(bytes.TrimSpace(rest), []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, errors.New("CA文件須仅含PEM证书")
		}
		block, next := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, errors.New("CA文件须仅含有效PEM证书")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, errors.New("CA证书解析失败")
		}
		roots.AddCert(certificate)
		count++
		rest = next
	}
	if count == 0 {
		return nil, errors.New("CA文件没有证书")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	return &http.Client{Transport: transport, Timeout: 15 * time.Second}, nil
}
