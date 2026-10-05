package windowsservice

import "time"

// drainFailure 保留 caller 的配置/二进制 pins，直到全部 worker 和 profile lease 完成。
// 专用 SCM 进程的 terminate 成功时不返回；失败时继续等待真实 drain，不能提前返回 Stopped。
func drainFailure(done <-chan error, ticks <-chan time.Time, terminate func(), heartbeat func()) error {
	terminate()
	for {
		select {
		case err := <-done:
			if err != ErrCleanup {
				return err
			}
			// lease 清理失败时不能按成功 stop 释放 pins。终止失败则保持永久 StopPending。
			done = nil
			terminate()
		case <-ticks:
			heartbeat()
		}
	}
}
