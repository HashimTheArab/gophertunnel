package protocol

type MemoryCategory uint8

const (
	MemoryCategoryUnknown                               MemoryCategory = 0
	MemoryCategoryInvalidSizeUnknown                    MemoryCategory = 1
	MemoryCategoryActor                                 MemoryCategory = 2
	MemoryCategoryActorAnimation                        MemoryCategory = 3
	MemoryCategoryActorRendering                        MemoryCategory = 4
	MemoryCategoryBalancer                              MemoryCategory = 5
	MemoryCategoryBlockTickingQueues                    MemoryCategory = 6
	MemoryCategoryBiomeStorage                          MemoryCategory = 7
	MemoryCategoryBlobs                                 MemoryCategory = 8
	MemoryCategoryCereal                                MemoryCategory = 9
	MemoryCategoryCircuitSystem                         MemoryCategory = 10
	MemoryCategoryClient                                MemoryCategory = 11
	MemoryCategoryCommands                              MemoryCategory = 12
	MemoryCategoryDBStorage                             MemoryCategory = 13
	MemoryCategoryDebug                                 MemoryCategory = 14
	MemoryCategoryDocumentation                         MemoryCategory = 15
	MemoryCategoryECSSystems                            MemoryCategory = 16
	MemoryCategoryFMOD                                  MemoryCategory = 17
	MemoryCategoryFonts                                 MemoryCategory = 18
	MemoryCategoryImGUI                                 MemoryCategory = 19
	MemoryCategoryInput                                 MemoryCategory = 20
	MemoryCategoryJsonUI                                MemoryCategory = 21
	MemoryCategoryJsonUIControlFactoryJson              MemoryCategory = 22
	MemoryCategoryJsonUIControlTree                     MemoryCategory = 23
	MemoryCategoryJsonUIControlTreeControlElement       MemoryCategory = 24
	MemoryCategoryJsonUIControlTreePopulateDataBinding  MemoryCategory = 25
	MemoryCategoryJsonUIControlTreePopulateFocus        MemoryCategory = 26
	MemoryCategoryJsonUIControlTreePopulateLayout       MemoryCategory = 27
	MemoryCategoryJsonUIControlTreePopulateOther        MemoryCategory = 28
	MemoryCategoryJsonUIControlTreePopulateSprite       MemoryCategory = 29
	MemoryCategoryJsonUIControlTreePopulateText         MemoryCategory = 30
	MemoryCategoryJsonUIControlTreePopulateTTS          MemoryCategory = 31
	MemoryCategoryJsonUIControlTreeVisibility           MemoryCategory = 32
	MemoryCategoryJsonUICreateUI                        MemoryCategory = 33
	MemoryCategoryJsonUIDefs                            MemoryCategory = 34
	MemoryCategoryJsonUILayoutManager                   MemoryCategory = 35
	MemoryCategoryJsonUILayoutManagerRemoveDependencies MemoryCategory = 36
	MemoryCategoryJsonUILayoutManagerInitVariable       MemoryCategory = 37
	MemoryCategoryLanguages                             MemoryCategory = 38
	MemoryCategoryLevel                                 MemoryCategory = 39
	MemoryCategoryLevelStructures                       MemoryCategory = 40
	MemoryCategoryLevelChunk                            MemoryCategory = 41
	MemoryCategoryLevelChunkGen                         MemoryCategory = 42
	MemoryCategoryLevelChunkGenThreadLocal              MemoryCategory = 43
	MemoryCategoryNetwork                               MemoryCategory = 44
	MemoryCategoryMarketplace                           MemoryCategory = 45
	MemoryCategoryMaterialDragonCompiledDefinition      MemoryCategory = 46
	MemoryCategoryMaterialDragonMaterial                MemoryCategory = 47
	MemoryCategoryMaterialDragonResource                MemoryCategory = 48
	MemoryCategoryMaterialDragonUniformMap              MemoryCategory = 49
	MemoryCategoryMaterialRenderMaterial                MemoryCategory = 50
	MemoryCategoryMaterialRenderMaterialGroup           MemoryCategory = 51
	MemoryCategoryMaterialVariationManager              MemoryCategory = 52
	MemoryCategoryMolang                                MemoryCategory = 53
	MemoryCategoryOreUI                                 MemoryCategory = 54
	MemoryCategoryOreUIClient                           MemoryCategory = 55
	MemoryCategoryPersonaPieces                         MemoryCategory = 56
	MemoryCategoryPersonaAnimations                     MemoryCategory = 57
	MemoryCategoryPersonaCharacters                     MemoryCategory = 58
	MemoryCategoryPersonaSkinPacks                      MemoryCategory = 59
	MemoryCategoryPersonaRepo                           MemoryCategory = 60
	MemoryCategoryPlayer                                MemoryCategory = 61
	MemoryCategoryRenderChunk                           MemoryCategory = 62
	MemoryCategoryRenderChunkIndexBuffer                MemoryCategory = 63
	MemoryCategoryRenderChunkVertexBuffer               MemoryCategory = 64
	MemoryCategoryRendering                             MemoryCategory = 65
	MemoryCategoryRenderingBGFXInit                     MemoryCategory = 66
	MemoryCategoryRenderingBGFXStartFrame               MemoryCategory = 67
	MemoryCategoryRenderingBlockTessellator             MemoryCategory = 68
	MemoryCategoryRenderingEndFrame                     MemoryCategory = 69
	MemoryCategoryRenderingGraphicsTasksInit            MemoryCategory = 70
	MemoryCategoryRenderingLibrary                      MemoryCategory = 71
	MemoryCategoryRenderingPolygonOperatorPool          MemoryCategory = 72
	MemoryCategoryRenderingPBRTextureData               MemoryCategory = 73
	MemoryCategoryRenderingRenderRegistry               MemoryCategory = 74
	MemoryCategoryRenderingSetup                        MemoryCategory = 75
	MemoryCategoryRenderingVertices                     MemoryCategory = 76
	MemoryCategoryRequestLog                            MemoryCategory = 77
	MemoryCategoryResourcePacks                         MemoryCategory = 78
	MemoryCategorySound                                 MemoryCategory = 79
	MemoryCategorySubChunkBiomeData                     MemoryCategory = 80
	MemoryCategorySubChunkBlockData                     MemoryCategory = 81
	MemoryCategorySubChunkLightData                     MemoryCategory = 82
	MemoryCategoryTextures                              MemoryCategory = 83
	MemoryCategoryWeatherRenderer                       MemoryCategory = 84
	MemoryCategoryWorldGenerator                        MemoryCategory = 85
	MemoryCategoryTasks                                 MemoryCategory = 86
	MemoryCategoryTest                                  MemoryCategory = 87
	MemoryCategoryTestLoadTestTags                      MemoryCategory = 88
	MemoryCategoryScripting                             MemoryCategory = 89
	MemoryCategoryScriptingRuntime                      MemoryCategory = 90
	MemoryCategoryScriptingContext                      MemoryCategory = 91
	MemoryCategoryScriptingContextBindingsMC            MemoryCategory = 92
	MemoryCategoryScriptingContextBindingsGT            MemoryCategory = 93
	MemoryCategoryScriptingContextRun                   MemoryCategory = 94
	MemoryCategoryDataDrivenUI                          MemoryCategory = 95
	MemoryCategoryDataDrivenUIDefs                      MemoryCategory = 96
	MemoryCategoryGameface                              MemoryCategory = 97
	MemoryCategoryGamefaceSystem                        MemoryCategory = 98
	MemoryCategoryGamefaceDOM                           MemoryCategory = 99
	MemoryCategoryGamefaceCSS                           MemoryCategory = 100
	MemoryCategoryGamefaceDisplay                       MemoryCategory = 101
	MemoryCategoryGamefaceTempAllocator                 MemoryCategory = 102
	MemoryCategoryGamefacePoolAllocator                 MemoryCategory = 103
	MemoryCategoryGamefaceDump                          MemoryCategory = 104
	MemoryCategoryGamefaceMedia                         MemoryCategory = 105
	MemoryCategoryGamefaceJSON                          MemoryCategory = 106
	MemoryCategoryGamefaceScriptEngine                  MemoryCategory = 107
	MemoryCategoryGamefaceScript                        MemoryCategory = 108
	MemoryCategoryGamefaceLayout                        MemoryCategory = 109
	MemoryCategoryVR                                    MemoryCategory = 110
)

// Marshal reads or writes MemoryCategory through its uint8 wire encoding.
func (x *MemoryCategory) Marshal(io IO) { io.Uint8((*uint8)(x)) }

// MemoryCategoryCounter represents a memory usage counter for a specific category.
type MemoryCategoryCounter struct {
	// Category is the memory category. It is one of the MemoryCategory constants above.
	Category MemoryCategory
	// Bytes is the number of bytes used by this category.
	Bytes uint64
}

// Marshal reads or writes MemoryCategoryCounter using its canonical wire layout.
func (x *MemoryCategoryCounter) Marshal(io IO) {
	x.Category.Marshal(io)
	io.Uint64(&x.Bytes)
}

// ECSProfilingDiagnosticsSystemCategory maps a diagnostics category name to a system index.
type SystemCategory struct {
	CategoryName string
	SystemIndex  uint64
}

// Marshal reads or writes SystemCategory using its canonical wire layout.
func (x *SystemCategory) Marshal(io IO) {
	io.String(&x.CategoryName)
	io.Uint64(&x.SystemIndex)
}

// ECSProfilingDiagnosticsSystemDiagnosticTimingInfo represents diagnostics for a specific system index.
type SystemDiagnosticTimingInfo struct {
	// DisplayName is the name to display for this timing entry.
	DisplayName string
	// SystemIndex is the index of the system that is being timed.
	SystemIndex uint64
	// DurationNanos is whole long the timing entry has lasted, in nanoseconds.
	DurationNanos uint64
	// PercentOfTotal is the percentage of time that this timing entry has used compared to others.
	PercentOfTotal uint8
}

// Marshal reads or writes SystemDiagnosticTimingInfo using its canonical wire layout.
func (x *SystemDiagnosticTimingInfo) Marshal(io IO) {
	io.String(&x.DisplayName)
	io.Uint64(&x.SystemIndex)
	io.Uint64(&x.DurationNanos)
	io.Uint8(&x.PercentOfTotal)
}

// BedrockProfileWhiskerDiagnosticsScopeDataSummary represents a whisker profiler scope diagnostic summary.
type WhiskerScopeDataSummary struct {
	// Label is the label of the whisker scope.
	Label string
	// Indentation is the indentation string of the whisker scope within the profiler hierarchy.
	Indentation string
	// TotalHighCostNS is the total time, in nanoseconds, spent in the high-cost portion of the scope.
	TotalHighCostNS uint64
	// TotalMidCostNS is the total time, in nanoseconds, spent in the mid-cost portion of the scope.
	TotalMidCostNS uint64
	// TotalLowCostNS is the total time, in nanoseconds, spent in the low-cost portion of the scope.
	TotalLowCostNS uint64
}

// Marshal reads or writes WhiskerScopeDataSummary using its canonical wire layout.
func (x *WhiskerScopeDataSummary) Marshal(io IO) {
	io.String(&x.Label)
	io.String(&x.Indentation)
	io.Uint64(&x.TotalHighCostNS)
	io.Uint64(&x.TotalMidCostNS)
	io.Uint64(&x.TotalLowCostNS)
}
