package syncclient

// WriteOperationInfo 是受保护日志的有限元数据，不含变量名、值、密文或签包。
// 未应用不证明尚未提交；调用方只能以原 RequestID 使用 Operation=retry。
type WriteOperationInfo struct {
	RequestID     string   `json:"requestId"`
	Operation     string   `json:"operation"`
	EnvironmentID string   `json:"environmentId"`
	Total         int      `json:"total"`
	Accepted      int      `json:"accepted"`
	Applied       bool     `json:"applied"`
	Canceled      bool     `json:"canceled"`
	Sequences     []uint64 `json:"sequences"`
}

// PendingRequests 在原生日志已完成签名及账号/epoch校验后只列出未应用项。
// canceled项保留ID墓碑，不提供重新签包或恢复提交的资格。
func (w *Writer) PendingRequests() ([]WriteOperationInfo, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil, ErrWriteJournal
	}
	items := make([]WriteOperationInfo, 0, len(w.log.Records))
	for _, r := range w.log.Records {
		if r.Applied {
			continue
		}
		info, err := operationInfo(r)
		if err != nil {
			return nil, err
		}
		items = append(items, info)
	}
	return items, nil
}

// OperationInfo 允许原ID在最后保护保存及响应丢失后确认已应用的本机记录。
// 查不到原ID时拒绝，不提供建立新请求或重签的路径。
func (w *Writer) OperationInfo(id string) (WriteOperationInfo, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return WriteOperationInfo{}, ErrWriteJournal
	}
	if !requestIDPattern.MatchString(id) {
		return WriteOperationInfo{}, ErrWriteInput
	}
	for _, r := range w.log.Records {
		if r.RequestID == id {
			return operationInfo(r)
		}
	}
	return WriteOperationInfo{}, ErrWriteConflict
}

func operationInfo(r writeRecord) (WriteOperationInfo, error) {
	if len(r.Items) == 0 {
		return WriteOperationInfo{}, ErrWriteJournal
	}
	env, operation := r.Items[0].Mutation.Mutation.EnvironmentID, r.Items[0].Mutation.Mutation.Operation
	for _, item := range r.Items {
		if item.Mutation.Mutation.EnvironmentID != env || item.Mutation.Mutation.Operation != operation {
			return WriteOperationInfo{}, ErrWriteJournal
		}
	}
	if operation != "put" && operation != "delete" {
		return WriteOperationInfo{}, ErrWriteJournal
	}
	if len(r.Items) > 1 {
		if operation != "put" {
			return WriteOperationInfo{}, ErrWriteJournal
		}
		operation = "import"
	}
	result := recordResult(r)
	return WriteOperationInfo{RequestID: r.RequestID, Operation: operation,
		EnvironmentID: env, Total: result.Total, Accepted: result.Accepted,
		Applied: result.Applied, Canceled: r.Canceled, Sequences: result.Sequences}, nil
}
