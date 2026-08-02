package smartlock

type DeviceID string
type TraceID string
type StateName string

const (
	DemoDeviceID  DeviceID  = "demo-front-door"
	UnlockTool              = "smart_lock.unlock"
	StateLocked   StateName = "locked"
	StateUnlocked StateName = "unlocked"
)

type Arguments struct {
	DeviceID DeviceID `json:"device_id"`
}

type Operation struct {
	Tool      string    `json:"tool"`
	Arguments Arguments `json:"arguments"`
	TraceID   TraceID   `json:"trace_id"`
	Approval  string    `json:"approval"`
}

type State struct {
	DeviceID DeviceID  `json:"device_id"`
	State    StateName `json:"state"`
}
