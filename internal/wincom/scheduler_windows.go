//go:build windows

// Package wincom 为受信源码提供本机 Task Scheduler；不接收网络/IPC 的方法名或路径。
package wincom

import (
	"errors"
	"runtime"
	"unsafe"

	ole "github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	"golang.org/x/sys/windows"
)

var ErrCOM = errors.New("local task scheduler operation rejected")

// Failure 仅保留固定错误类别和数值；不得携带 COM Description/Source/HelpFile。
type Failure struct {
	CodeRecorded   bool
	HRESULT        uint32
	ExceptionSCODE uint32
	ExceptionWCode uint16
}

func (*Failure) Error() string { return ErrCOM.Error() }
func (*Failure) Unwrap() error { return ErrCOM }

func numericFailure(err error) error {
	failure := &Failure{}
	var original *ole.OleError
	if errors.As(err, &original) {
		failure.CodeRecorded = true
		failure.HRESULT = uint32(original.Code())
		switch exception := original.SubError().(type) {
		case ole.EXCEPINFO:
			failure.ExceptionSCODE = exception.SCODE()
			failure.ExceptionWCode = exception.WCode()
		case *ole.EXCEPINFO:
			if exception != nil {
				failure.ExceptionSCODE = exception.SCODE()
				failure.ExceptionWCode = exception.WCode()
			}
		}
	}
	return failure
}

var create = windows.NewLazySystemDLL("ole32.dll").NewProc("CoCreateInstance")

// Microsoft taskschd.h 的 CLSID_TaskScheduler，明确只本机 INPROC 对象，不用调用方 ProgID/远端位置。
var schedulerCLSID = ole.NewGUID("{0F87369F-A4E5-4CFC-BD3E-73E6154572DD}")

type Session struct {
	Root    *ole.IDispatch
	objects []*ole.VARIANT
}

func Open() (*Session, error) {
	runtime.LockOSThread()
	if err := ole.CoInitializeEx(0, ole.COINIT_APARTMENTTHREADED); err != nil {
		if e, ok := err.(*ole.OleError); !ok || e.Code() != 1 {
			runtime.UnlockOSThread()
			return nil, numericFailure(err)
		}
	}
	s := &Session{}
	result, _, _ := create.Call(uintptr(unsafe.Pointer(schedulerCLSID)), 0, 1, uintptr(unsafe.Pointer(ole.IID_IDispatch)), uintptr(unsafe.Pointer(&s.Root)))
	if uint32(result) != 0 || s.Root == nil {
		ole.CoUninitialize()
		runtime.UnlockOSThread()
		return nil, &Failure{CodeRecorded: true, HRESULT: uint32(result)}
	}
	if _, e := s.Call(s.Root, "Connect"); e != nil {
		s.Close()
		return nil, e
	}
	return s, nil
}

// Close 必须在 Open 的同一 goroutine 内调用，全部接口释放后才解除 OS thread。
func (s *Session) Close() {
	for i := len(s.objects) - 1; i >= 0; i-- {
		_ = s.objects[i].Clear()
	}
	s.objects = nil
	if s.Root != nil {
		s.Root.Release()
		s.Root = nil
	}
	ole.CoUninitialize()
	runtime.UnlockOSThread()
}
func (s *Session) result(v *ole.VARIANT, err error) (*ole.VARIANT, error) {
	if err != nil {
		if v != nil {
			_ = v.Clear()
		}
		return nil, numericFailure(err)
	}
	if v == nil {
		return nil, ErrCOM
	}
	s.objects = append(s.objects, v)
	return v, nil
}
func (s *Session) Call(o *ole.IDispatch, name string, args ...any) (*ole.VARIANT, error) {
	v, e := oleutil.CallMethod(o, name, args...)
	return s.result(v, e)
}
func (s *Session) Get(o *ole.IDispatch, name string) (*ole.VARIANT, error) {
	v, e := oleutil.GetProperty(o, name)
	return s.result(v, e)
}
func (s *Session) Object(o *ole.IDispatch, name string, args ...any) (*ole.IDispatch, error) {
	v, e := s.Call(o, name, args...)
	if e != nil {
		return nil, e
	}
	d := v.ToIDispatch()
	if d == nil {
		return nil, ErrCOM
	}
	return d, nil
}
func (s *Session) String(o *ole.IDispatch, name string, args ...any) (string, error) {
	v, e := s.Call(o, name, args...)
	if e != nil || v.VT != ole.VT_BSTR {
		return "", ErrCOM
	}
	return v.ToString(), nil
}
func (s *Session) PropertyString(o *ole.IDispatch, name string) (string, error) {
	v, e := s.Get(o, name)
	if e != nil || v.VT != ole.VT_BSTR {
		return "", ErrCOM
	}
	return v.ToString(), nil
}
func (s *Session) Number(o *ole.IDispatch, name string) (int64, error) {
	v, e := s.Get(o, name)
	if e != nil {
		return 0, e
	}
	if v.VT != ole.VT_I4 && v.VT != ole.VT_INT && v.VT != ole.VT_UI4 {
		return 0, ErrCOM
	}
	return v.Val, nil
}
