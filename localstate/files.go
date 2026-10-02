package localstate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

const maxFileSize = 16 << 20

type FileStore struct {
	path string
	lock *os.File
	mu   sync.Mutex
}

// OpenFileStore 获取进程级独占锁；daemon 与 CLI 不会并发丢失状态。
// 状态含本地明文缓存，必须放在当前用户私有目录；正式服务仍须机器保护层。
func OpenFileStore(path string) (*FileStore, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	dir := filepath.Dir(path)
	if err = os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	if err = privateDirectory(dir); err != nil {
		return nil, err
	}
	lockPath := path + ".lock"
	if err = rejectSymlink(lockPath); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = lockFile(f); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("state is busy: %w", err)
	}
	return &FileStore{path: path, lock: f}, nil
}
func (s *FileStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lock == nil {
		return nil
	}
	err := unlockFile(s.lock)
	closeErr := s.lock.Close()
	s.lock = nil
	return errors.Join(err, closeErr)
}
func (s *FileStore) Load() (State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lock == nil {
		return State{}, errors.New("store closed")
	}
	var state State
	err := readJSON(s.path, &state)
	if errors.Is(err, os.ErrNotExist) {
		return EmptyState(), nil
	}
	return state, err
}
func (s *FileStore) Save(state State) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lock == nil {
		return errors.New("store closed")
	}
	return atomicJSON(s.path, state)
}
func rejectSymlink(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("symlink path is forbidden")
	}
	return nil
}
func readJSON(path string, dst any) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("only regular JSON files are supported")
	}
	if err = privateFile(info); err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(info, opened) {
		return errors.New("JSON file changed while opening")
	}
	if opened.Size() > maxFileSize {
		return errors.New("JSON file is too large")
	}
	dec := json.NewDecoder(io.LimitReader(f, maxFileSize+1))
	dec.DisallowUnknownFields()
	if err = dec.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err = dec.Decode(&extra); err != io.EOF {
		return errors.New("JSON file must contain one object")
	}
	return nil
}
func atomicJSON(path string, value any) error {
	if err := rejectSymlink(path); err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if err := privateDirectory(dir); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".harmonia-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	fail := func(err error) error { _ = f.Close(); return err }
	if err = f.Chmod(0600); err != nil {
		return fail(err)
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err = enc.Encode(value); err != nil {
		return fail(err)
	}
	if err = f.Sync(); err != nil {
		return fail(err)
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmp, path); err != nil {
		return err
	}
	return syncDirectory(dir)
}

// FileProvider 只用于明确指定的隔离 JSON fixture，绝不读取宿主真实环境。
// 每次 Apply 重新读取当前文件，因此未托管项的外部修改得以保留。
type FileProvider struct {
	Path string
	mu   sync.Mutex
}

func (p *FileProvider) Snapshot(ctx context.Context, keys []string) (map[string]string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	values, err := p.load()
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, key := range keys {
		if value, ok := values[key]; ok {
			out[key] = value
		}
	}
	return out, nil
}
func (p *FileProvider) load() (map[string]string, error) {
	values := map[string]string{}
	err := readJSON(p.Path, &values)
	if errors.Is(err, os.ErrNotExist) {
		return values, nil
	}
	if err != nil {
		return nil, err
	}
	for k, v := range values {
		if err := validateValue(k, v); err != nil {
			return nil, err
		}
	}
	return values, nil
}
func (p *FileProvider) Apply(ctx context.Context, changes []Change) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	values, err := p.load()
	if err != nil {
		return err
	}
	for _, change := range changes {
		if change.Value == nil {
			delete(values, change.Name)
		} else {
			if err := validateValue(change.Name, *change.Value); err != nil {
				return err
			}
			values[change.Name] = *change.Value
		}
	}
	return atomicJSON(p.Path, values)
}
