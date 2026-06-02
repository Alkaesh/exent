package conduit

import (
    "encoding/json"
    "fmt"
    "sync"
)

type HandlerFunc func(msg *Message) error

type Server struct {
    cfg      ServerConfig
    handlers map[string]HandlerFunc
    lock     sync.RWMutex
    started  bool
}

func NewServer(cfg ServerConfig) *Server {
    return &Server{
        cfg:      cfg,
        handlers: make(map[string]HandlerFunc),
    }
}

func (s *Server) Handle(id int, key string, handler HandlerFunc) {
    s.lock.Lock()
    defer s.lock.Unlock()
    s.handlers[key] = handler
}

func (s *Server) Start() error {
    if s.started {
        return nil
    }
    s.started = true
    fmt.Println("conduit: server started on channel", s.cfg.ChannelName)
    return nil
}

func (s *Server) Stop() {
    fmt.Println("conduit: server stopped")
}

func (s *Server) Send(msg *Message) error {
    s.lock.RLock()
    handler, ok := s.handlers[msg.Command]
    s.lock.RUnlock()
    if !ok {
        return fmt.Errorf("conduit: unknown command %s", msg.Command)
    }
    return handler(msg)
}

func (s *Server) DispatchRaw(raw []byte) error {
    var msg Message
    if err := json.Unmarshal(raw, &msg); err != nil {
        return err
    }
    return s.Send(&msg)
}
