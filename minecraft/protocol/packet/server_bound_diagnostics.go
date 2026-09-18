package packet

import "github.com/sandertv/gophertunnel/minecraft/protocol"

type ServerboundDiagnostics struct {
	AverageFramesPerSecond        float32
	AverageServerSimTickTime      float32
	AverageClientSimTickTime      float32
	AverageBeginFrameTime         float32
	AverageInputTime              float32
	AverageRenderTime             float32
	AverageEndFrameTime           float32
	AverageRemainderTimePercent   float32
	AverageUnaccountedTimePercent float32
	MemoryCategoryValues          []protocol.MemoryCategoryCounter
	EntityDiagnostics             []protocol.ECSProfilingDiagnosticsEntityDiagnosticTimingInfo
	SystemDiagnostics             []protocol.ECSProfilingDiagnosticsSystemDiagnosticTimingInfo
	SystemCategories              []protocol.ECSProfilingDiagnosticsSystemCategory
	WhiskerScopes                 []protocol.BedrockProfileWhiskerDiagnosticsScopeDataSummary
}

// Marshal reads or writes ServerboundDiagnostics using its canonical wire layout.
func (x *ServerboundDiagnostics) Marshal(io protocol.IO) {
	io.Float32(&x.AverageFramesPerSecond)
	io.Float32(&x.AverageServerSimTickTime)
	io.Float32(&x.AverageClientSimTickTime)
	io.Float32(&x.AverageBeginFrameTime)
	io.Float32(&x.AverageInputTime)
	io.Float32(&x.AverageRenderTime)
	io.Float32(&x.AverageEndFrameTime)
	io.Float32(&x.AverageRemainderTimePercent)
	io.Float32(&x.AverageUnaccountedTimePercent)
	protocol.Slice(io, &x.MemoryCategoryValues)
	protocol.Slice(io, &x.EntityDiagnostics)
	protocol.Slice(io, &x.SystemDiagnostics)
	protocol.Slice(io, &x.SystemCategories)
	protocol.Slice(io, &x.WhiskerScopes)
}

// ID returns the protocol ID for ServerboundDiagnostics.
func (*ServerboundDiagnostics) ID() uint32 { return IDServerboundDiagnostics }
