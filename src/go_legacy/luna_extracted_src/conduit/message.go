package conduit

import "encoding/json"

type Message struct {
    Command string          `json:"command"`
    Payload json.RawMessage `json:"payload"`
}

func (m *Message) UnmarshalPayload(v interface{}) error {
    return json.Unmarshal(m.Payload, v)
}

func (m *Message) Marshal() ([]byte, error) {
    return json.Marshal(m)
}
