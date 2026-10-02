package localkeys

// secureFS 限制所有操作在持有锁和目录句柄的一个私有目录内。
type secureFS interface {
	Read(name string, max int) ([]byte, error)
	Write(name string, data []byte, exclusive bool) error
	Delete(name string) error
	Close() error
}
