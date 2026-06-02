package main

/*
#include <stdint.h>
*/
import "C"
import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/roblox/luna_extracted/api"
	"github.com/roblox/luna_extracted/conduit"
	lua "github.com/yuin/gopher-lua"
)

const (
	channelName      = "LUNA_SHARED_MEM"
	commandExecute   = "CTR-EXECUTE"
	commandCheckFreq = 300 * time.Millisecond
	queueCheckFreq   = 50 * time.Millisecond
)

var (
	executionQueue api.Queue[api.ExecutionItem]
	server         *conduit.Server
	startOnce      sync.Once
	overlayActive  = true
	historyMu      sync.Mutex
	history        []string
	luaMu          sync.Mutex
	luaState       *lua.LState
	queueMu        sync.Mutex
	runtimeReady   atomic.Bool
	logMu          sync.Mutex

	user32          = syscall.NewLazyDLL("user32.dll")
	procMessageBoxW = user32.NewProc("MessageBoxW")
)

type executePayload struct {
	Source string `json:"source"`
	Type   string `json:"type,omitempty"`
}

type commandPayload struct {
	ID     string `json:"id"`
	Type   string `json:"type"`
	Script string `json:"script"`
}

type runtimeStatus struct {
	PID       int    `json:"pid"`
	Status    string `json:"status"`
	LogPath   string `json:"log_path,omitempty"`
	Message   string `json:"message,omitempty"`
	UpdatedAt string `json:"updated_at"`
}

type commandAck struct {
	ID        string `json:"id"`
	Status    string `json:"status"`
	Message   string `json:"message,omitempty"`
	LogPath   string `json:"log_path,omitempty"`
	UpdatedAt string `json:"updated_at"`
}

type logEntry struct {
	Timestamp string `json:"timestamp"`
	Level     string `json:"level"`
	Event     string `json:"event"`
	PID       int    `json:"pid"`
	CommandID string `json:"command_id,omitempty"`
	Status    string `json:"status,omitempty"`
	Message   string `json:"message,omitempty"`
	Details   string `json:"details,omitempty"`
}

func main() {}

func init() {
	// Keep loader-time initialization minimal to avoid deadlocks under the Windows loader lock.
}

func ensureRuntimeStarted() {
	startOnce.Do(func() {
		runtime.GOMAXPROCS(1)
		if err := ensureRuntimeDirectories(); err != nil {
			fmt.Println("luna_extracted: failed to prepare runtime directories:", err)
			return
		}
		logRuntimeEvent("info", "runtime.bootstrap", "", "started", "runtime bootstrap started", "")

		cfg := conduit.DefaultServerConfig()
		cfg.ChannelName = channelName

		server = conduit.NewServer(cfg)
		server.Handle(7, commandExecute, handleExecuteCommand)

		if err := server.Start(); err != nil {
			fmt.Println("luna_extracted: conduit server failed to start:", err)
			logRuntimeEvent("error", "conduit.start", "", "failed", "conduit server failed to start", err.Error())
		} else {
			fmt.Println("luna_extracted: conduit server started on", cfg.ChannelName)
			logRuntimeEvent("info", "conduit.start", "", "started", "conduit server started", cfg.ChannelName)
		}

		go startCommandWatcher()
		go startQueueProcessor()

		runtimeReady.Store(true)
		if err := writeRuntimeStatus("runtime_ready", "runtime initialized"); err != nil {
			fmt.Println("luna_extracted: failed to write ready status:", err)
			logRuntimeEvent("error", "runtime.ready_file", "", "failed", "failed to write ready status", err.Error())
		} else {
			fmt.Println("luna_extracted: runtime ready")
			logRuntimeEvent("info", "runtime.ready", "", "confirmed", "runtime ready", "")
		}
	})
}

func handleExecuteCommand(msg *conduit.Message) error {
	ensureRuntimeStarted()

	var data executePayload
	if err := msg.UnmarshalPayload(&data); err != nil {
		fmt.Println("luna_extracted: invalid execute payload:", err)
		logRuntimeEvent("error", "conduit.execute", "", "rejected", "invalid execute payload", err.Error())
		return err
	}

	item := api.ExecutionItem{
		Source: []byte(data.Source),
		Type:   api.ExecutionTypeSource,
	}
	if data.Type == "yield" {
		item.Type = api.ExecutionTypeYield
		item.Yield = &api.YieldData{Value: data.Source}
	}

	executionQueue.Push(item)
	fmt.Println("luna_extracted: queued source item; queue length=", executionQueue.Len())
	logRuntimeEvent("info", "conduit.execute", "", "accepted", "execute payload queued", fmt.Sprintf("queue_length=%d", executionQueue.Len()))
	return nil
}

func startCommandWatcher() {
	for {
		time.Sleep(commandCheckFreq)
		if err := scanCommandDirectory(); err != nil {
			fmt.Println("luna_extracted: command watcher error:", err)
			logRuntimeEvent("error", "command.scan", "", "failed", "command watcher error", err.Error())
		}
	}
}

func startQueueProcessor() {
	for {
		time.Sleep(queueCheckFreq)
		processQueue()
	}
}

func runtimeBaseDir() string {
	return filepath.Join(os.TempDir(), "luna_extracted", strconv.Itoa(os.Getpid()))
}

func commandDir() string {
	return filepath.Join(runtimeBaseDir(), "commands")
}

func ackDir() string {
	return filepath.Join(runtimeBaseDir(), "acks")
}

func readyFilePath() string {
	return filepath.Join(runtimeBaseDir(), "ready.json")
}

func runtimeLogPath() string {
	return filepath.Join(runtimeBaseDir(), "runtime.log")
}

func ackPathForID(id string) string {
	return filepath.Join(ackDir(), id+".json")
}

func ensureRuntimeDirectories() error {
	if err := os.MkdirAll(commandDir(), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(ackDir(), 0o755); err != nil {
		return err
	}
	return nil
}

func writeJSONAtomic(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}

	tempPath := path + ".tmp"
	if err := os.WriteFile(tempPath, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tempPath, path)
}

func logRuntimeEvent(level, event, commandID, status, message, details string) {
	entry := logEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Level:     level,
		Event:     event,
		PID:       os.Getpid(),
		CommandID: commandID,
		Status:    status,
		Message:   message,
		Details:   details,
	}

	data, err := json.Marshal(entry)
	if err != nil {
		fmt.Println("luna_extracted: failed to marshal log entry:", err)
		return
	}

	logMu.Lock()
	defer logMu.Unlock()

	if err := os.MkdirAll(filepath.Dir(runtimeLogPath()), 0o755); err != nil {
		fmt.Println("luna_extracted: failed to create log directory:", err)
		return
	}

	file, err := os.OpenFile(runtimeLogPath(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		fmt.Println("luna_extracted: failed to open runtime log:", err)
		return
	}
	defer file.Close()

	if _, err := file.Write(append(data, '\n')); err != nil {
		fmt.Println("luna_extracted: failed to write runtime log:", err)
	}
}

func writeRuntimeStatus(status, message string) error {
	return writeJSONAtomic(readyFilePath(), runtimeStatus{
		PID:       os.Getpid(),
		Status:    status,
		LogPath:   runtimeLogPath(),
		Message:   message,
		UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano),
	})
}

func writeCommandAck(id, status, message string) error {
	if id == "" {
		return errors.New("empty command id")
	}
	return writeJSONAtomic(ackPathForID(id), commandAck{
		ID:        id,
		Status:    status,
		Message:   message,
		LogPath:   runtimeLogPath(),
		UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano),
	})
}

func scanCommandDirectory() error {
	entries, err := os.ReadDir(commandDir())
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		names = append(names, entry.Name())
	}
	sort.Strings(names)

	for _, name := range names {
		if err := processCommandFile(filepath.Join(commandDir(), name)); err != nil {
			fmt.Println("luna_extracted: failed to process command file:", name, err)
			logRuntimeEvent("error", "command.process_file", "", "failed", "failed to process command file", fmt.Sprintf("%s: %v", name, err))
		}
	}
	return nil
}

func processCommandFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if len(data) == 0 {
		logRuntimeEvent("warn", "command.file", "", "ignored", "empty command file", path)
		_ = os.Remove(path)
		return nil
	}

	var command commandPayload
	if err := json.Unmarshal(data, &command); err != nil {
		logRuntimeEvent("error", "command.file", "", "invalid", "invalid command file JSON", fmt.Sprintf("%s: %v", path, err))
		_ = os.Rename(path, path+".invalid")
		return err
	}
	if command.ID == "" {
		logRuntimeEvent("error", "command.file", "", "invalid", "command file missing id", path)
		_ = os.Rename(path, path+".invalid")
		return errors.New("missing command id")
	}

	if err := os.Remove(path); err != nil {
		logRuntimeEvent("error", "command.file", command.ID, "failed", "failed to remove processed command file", err.Error())
		return err
	}

	item := api.ExecutionItem{
		CommandID: command.ID,
		AckPath:   ackPathForID(command.ID),
	}
	switch command.Type {
	case "execute":
		item.Source = []byte(command.Script)
		item.Type = api.ExecutionTypeSource
	case "yield":
		item.Type = api.ExecutionTypeYield
		item.Yield = &api.YieldData{Value: command.Script}
	default:
		_ = writeCommandAck(command.ID, "rejected", "unknown command type: "+command.Type)
		logRuntimeEvent("warn", "command.accept", command.ID, "rejected", "unknown command type", command.Type)
		return fmt.Errorf("unknown command type: %s", command.Type)
	}

	executionQueue.Push(item)
	_ = writeCommandAck(command.ID, "accepted", "command queued for execution")
	fmt.Println("luna_extracted: queued command", command.ID, "queue length=", executionQueue.Len())
	logRuntimeEvent("info", "command.accept", command.ID, "accepted", "command queued for execution", fmt.Sprintf("type=%s queue_length=%d", command.Type, executionQueue.Len()))
	return nil
}

func recordHistory(entry string) {
	historyMu.Lock()
	history = append(history, fmt.Sprintf("%s: %s", time.Now().Format(time.RFC3339), entry))
	historyMu.Unlock()
}

func executeSource(src []byte) error {
	script := string(src)
	fmt.Println("luna_extracted: executing source:", script)
	if err := runScript(script); err != nil {
		fmt.Println("luna_extracted: execution error:", err)
		recordHistory("error: " + err.Error())
		return err
	}
	recordHistory("execute: " + script)
	return nil
}

func initLuaEngine() {
	luaMu.Lock()
	defer luaMu.Unlock()

	if luaState == nil {
		luaState = lua.NewState()
		luaState.SetGlobal("print", luaState.NewFunction(luaPrint))

		gameTable := luaState.NewTable()
		gameTable.RawSetString("GetService", luaState.NewFunction(luaGetService))
		luaState.SetGlobal("game", gameTable)
		logRuntimeEvent("info", "lua.init", "", "initialized", "lua runtime initialized", "")
	}
}

func luaPrint(L *lua.LState) int {
	args := make([]string, 0, L.GetTop())
	for i := 1; i <= L.GetTop(); i++ {
		args = append(args, L.ToStringMeta(L.Get(i)).String())
	}
	msg := strings.Join(args, "\t")
	fmt.Println("luna_extracted: lua print:", msg)
	recordHistory("lua.print: " + msg)
	logRuntimeEvent("info", "lua.print", "", "emitted", "lua print invoked", msg)
	showMessageBox("Luna Inject", msg)
	return 0
}

func showMessageBox(title, text string) {
	t, _ := syscall.UTF16PtrFromString(title)
	s, _ := syscall.UTF16PtrFromString(text)
	procMessageBoxW.Call(0, uintptr(unsafe.Pointer(s)), uintptr(unsafe.Pointer(t)), uintptr(0))
	logRuntimeEvent("info", "ui.message_box", "", "shown", "message box shown", title)
}

func luaGetService(L *lua.LState) int {
	var serviceName string
	if L.GetTop() >= 2 {
		serviceName = L.CheckString(2)
	} else {
		serviceName = L.CheckString(1)
	}
	table := L.NewTable()
	table.RawSetString("Name", lua.LString(serviceName))
	table.RawSetString("GetPlayers", luaState.NewFunction(func(L2 *lua.LState) int {
		L2.Push(lua.LNil)
		return 1
	}))
	L.Push(table)
	return 1
}

func runScript(script string) error {
	ensureRuntimeStarted()
	initLuaEngine()
	luaMu.Lock()
	defer luaMu.Unlock()
	return luaState.DoString(script)
}

func processYield(data *api.YieldData) {
	if data == nil {
		return
	}
	fmt.Println("luna_extracted: processing yield data:", data.Value)
	recordHistory("yield: " + data.Value)
	logRuntimeEvent("info", "queue.yield", "", "processed", "yield processed", data.Value)
}

func processRegister(data *api.RegisterData) {
	if data == nil {
		return
	}
	fmt.Println("luna_extracted: processing register:", data.Name, data.Value)
	recordHistory(fmt.Sprintf("register: %s=%s", data.Name, data.Value))
	logRuntimeEvent("info", "queue.register", "", "processed", "register processed", fmt.Sprintf("%s=%s", data.Name, data.Value))
}

func processQueue() {
	ensureRuntimeStarted()
	queueMu.Lock()
	defer queueMu.Unlock()

	for {
		item, ok := executionQueue.Pop()
		if !ok {
			return
		}

		var execErr error
		logRuntimeEvent("info", "queue.dispatch", item.CommandID, "started", "processing queue item", fmt.Sprintf("type=%d", item.Type))
		switch item.Type {
		case api.ExecutionTypeSource:
			execErr = executeSource(item.Source)
		case api.ExecutionTypeYield:
			processYield(item.Yield)
		case api.ExecutionTypeRegister:
			processRegister(item.Register)
		default:
			execErr = errors.New("unknown queue item type")
			fmt.Println("luna_extracted:", execErr.Error())
		}

		if item.CommandID != "" {
			status := "executed"
			message := "command processed successfully"
			if execErr != nil {
				status = "failed"
				message = execErr.Error()
			}
			if err := writeCommandAck(item.CommandID, status, message); err != nil {
				fmt.Println("luna_extracted: failed to write command ack:", err)
				logRuntimeEvent("error", "command.ack", item.CommandID, "failed", "failed to write command ack", err.Error())
			}
			level := "info"
			if execErr != nil {
				level = "error"
			}
			logRuntimeEvent(level, "queue.dispatch", item.CommandID, status, message, "")
		}
	}
}

//export DllMain
func DllMain() C.int {
	fmt.Println("luna_extracted: DllMain")
	return 1
}

//export StartRuntimeThreadProc
func StartRuntimeThreadProc(_ unsafe.Pointer) C.uint32_t {
	ensureRuntimeStarted()
	logRuntimeEvent("info", "export.StartRuntimeThreadProc", "", "called", "StartRuntimeThreadProc invoked", "")
	return 0
}

//export GoDrawLoop
func GoDrawLoop() {
	ensureRuntimeStarted()
	if overlayActive {
		fmt.Println("luna_extracted: GoDrawLoop - overlay render step")
		logRuntimeEvent("info", "export.GoDrawLoop", "", "called", "GoDrawLoop invoked", "")
	}
}

//export GoIndex
func GoIndex() {
	ensureRuntimeStarted()
	fmt.Println("luna_extracted: GoIndex invoked")
	logRuntimeEvent("info", "export.GoIndex", "", "called", "GoIndex invoked", "")
}

//export GoLunaGateway
func GoLunaGateway() {
	ensureRuntimeStarted()
	fmt.Println("luna_extracted: GoLunaGateway invoked")
	logRuntimeEvent("info", "export.GoLunaGateway", "", "called", "GoLunaGateway invoked", "")
}

//export GoNamecall
func GoNamecall() {
	ensureRuntimeStarted()
	fmt.Println("luna_extracted: GoNamecall invoked")
	logRuntimeEvent("info", "export.GoNamecall", "", "called", "GoNamecall invoked", "")
}

//export GoStepHookPayload
func GoStepHookPayload() {
	ensureRuntimeStarted()
	fmt.Println("luna_extracted: GoStepHookPayload start")
	logRuntimeEvent("info", "export.GoStepHookPayload", "", "called", "GoStepHookPayload invoked", "")
	processQueue()
}

//export ProcessQ
func ProcessQ() {
	ensureRuntimeStarted()
	fmt.Println("luna_extracted: ProcessQ start")
	logRuntimeEvent("info", "export.ProcessQ", "", "called", "ProcessQ invoked", "")
	processQueue()
}

//export ExecuteScript
func ExecuteScript(cscript *C.char) {
	ensureRuntimeStarted()
	script := C.GoString(cscript)
	executionQueue.Push(api.ExecutionItem{
		Source: []byte(script),
		Type:   api.ExecutionTypeSource,
	})
	fmt.Println("luna_extracted: ExecuteScript called; queue length=", executionQueue.Len())
	logRuntimeEvent("info", "export.ExecuteScript", "", "accepted", "ExecuteScript queued source", fmt.Sprintf("queue_length=%d", executionQueue.Len()))
}

//export free_go_handle
func free_go_handle() {
	fmt.Println("luna_extracted: free_go_handle called")
	logRuntimeEvent("info", "export.free_go_handle", "", "called", "free_go_handle invoked", "")
}

//export go_lua_callback
func go_lua_callback() {
	fmt.Println("luna_extracted: go_lua_callback called")
	logRuntimeEvent("info", "export.go_lua_callback", "", "called", "go_lua_callback invoked", "")
}
