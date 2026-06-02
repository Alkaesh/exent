package api

type ExecutionType int

const (
    ExecutionTypeUnknown ExecutionType = iota
    ExecutionTypeSource
    ExecutionTypeYield
    ExecutionTypeRegister
)

type YieldData struct {
    Value string `json:"value"`
}

type RegisterData struct {
    Name  string `json:"name"`
    Value string `json:"value"`
}

type ExecutionItem struct {
    CommandID string         `json:"command_id,omitempty"`
    AckPath   string         `json:"ack_path,omitempty"`
    Source    []byte         `json:"source"`
    Type      ExecutionType  `json:"type"`
    Yield     *YieldData     `json:"yield,omitempty"`
    Register  *RegisterData  `json:"register,omitempty"`
}
