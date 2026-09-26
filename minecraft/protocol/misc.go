package protocol

import (
	"image/color"

	"github.com/go-gl/mathgl/mgl32"
	"github.com/google/uuid"
)

type Achievement struct {
	AchievementID MinecraftEventingAchievementIds
}

func (*Achievement) tagEventData() uint32 { return 0 }

// Marshal reads or writes Achievement using its canonical wire layout.
func (x *Achievement) Marshal(io IO) {
	x.AchievementID.Marshal(io)
}

type AddEntry struct {
	Action           PlayerListPacketType
	UUID             uuid.UUID
	EntityUniqueID   int64
	PlayerName       string
	XBLXUID          string
	PlatformOnlineID string
	BuildPlatform    BuildPlatform
	SerializedSkin   SerializedSkinRef
	IsTeacher        bool
	IsHost           bool
	IsSubClient      bool
	PlayerColour     color.RGBA
}

func (*AddEntry) tagPlayerListData() uint32 { return 1 }

// Marshal reads or writes AddEntry using its canonical wire layout.
func (x *AddEntry) Marshal(io IO) {
	x.Action.Marshal(io)
	io.UUID(&x.UUID)
	io.ActorUniqueID(&x.EntityUniqueID)
	io.String(&x.PlayerName)
	io.String(&x.XBLXUID)
	io.String(&x.PlatformOnlineID)
	x.BuildPlatform.Marshal(io)
	x.SerializedSkin.Marshal(io)
	io.Bool(&x.IsTeacher)
	io.Bool(&x.IsHost)
	io.Bool(&x.IsSubClient)
	io.RGBA(&x.PlayerColour)
}

type AddTimeMarkerData struct {
	ClockID     uint64
	TimeMarkers []TimeMarkerData
}

func (*AddTimeMarkerData) tagSyncWorldClocksData() uint32 { return 2 }

// Marshal reads or writes AddTimeMarkerData using its canonical wire layout.
func (x *AddTimeMarkerData) Marshal(io IO) {
	io.Varuint64(&x.ClockID)
	SliceLimits(io, &x.TimeMarkers, 0, 256)
}

type AgentActionType int32

// Marshal reads or writes AgentActionType through its int32 wire encoding.
func (x *AgentActionType) Marshal(io IO) { io.Int32((*int32)(x)) }

type AgentAnimationType uint8

const (
	AgentAnimationTypeArmswing AgentAnimationType = 0
	AgentAnimationTypeShrug    AgentAnimationType = 1
)

// Marshal reads or writes AgentAnimationType through its uint8 wire encoding.
func (x *AgentAnimationType) Marshal(io IO) { io.Uint8((*uint8)(x)) }

type AnimateAction uint8

// Marshal reads or writes AnimateAction through its uint8 wire encoding.
func (x *AnimateAction) Marshal(io IO) { io.Uint8((*uint8)(x)) }

type AnimatedImageData struct {
	SkinImage           SkinImage
	AnimatedTextureType PersonaAnimatedTextureType
	Frames              float32
	AnimationExpression PersonaAnimationExpression
}

// Marshal reads or writes AnimatedImageData using its canonical wire layout.
func (x *AnimatedImageData) Marshal(io IO) {
	x.SkinImage.Marshal(io)
	x.AnimatedTextureType.Marshal(io)
	io.Float32(&x.Frames)
	x.AnimationExpression.Marshal(io)
}

type AuthorAndMessage struct {
	MessageType TextPacketType
	PlayerName  string
	Message     string
}

func (*AuthorAndMessage) tagTextData() uint32 { return 1 }

// Marshal reads or writes AuthorAndMessage using its canonical wire layout.
func (x *AuthorAndMessage) Marshal(io IO) {
	x.MessageType.Marshal(io)
	io.StringLimits(&x.PlayerName, 0, 256)
	io.StringLimits(&x.Message, 1, 65536)
}

type BedrockDDUI interface {
	Marshaler
	tagBedrockDDUI() uint32
}

// MarshalBedrockDDUI reads or writes the BedrockDDUI union using its canonical wire layout.
func MarshalBedrockDDUI(io IO, x *BedrockDDUI) {
	Union(io, x, io.Varuint32, BedrockDDUI.tagBedrockDDUI, func(tag uint32) BedrockDDUI {
		switch tag {
		case 0:
			return new(BedrockDDUIDataStoreUpdate)
		case 1:
			return new(DataStoreChange)
		case 2:
			return new(BedrockDDUIDataStoreRemoval)
		}
		return nil
	})
}

type BedrockDDUIDataStoreRemoval struct {
	DataStoreName string
}

func (*BedrockDDUIDataStoreRemoval) tagBedrockDDUI() uint32 { return 2 }

// Marshal reads or writes BedrockDDUIDataStoreRemoval using its canonical wire layout.
func (x *BedrockDDUIDataStoreRemoval) Marshal(io IO) {
	io.StringLimits(&x.DataStoreName, 1, 1000)
}

type BedrockDDUIDataStoreUpdate struct {
	DataStoreName       string
	Property            string
	Path                string
	Data                BedrockDDUIDataStoreUpdateData
	PropertyUpdateCount uint32
	PathUpdateCount     uint32
}

func (*BedrockDDUIDataStoreUpdate) tagBedrockDDUI() uint32 { return 0 }

// Marshal reads or writes BedrockDDUIDataStoreUpdate using its canonical wire layout.
func (x *BedrockDDUIDataStoreUpdate) Marshal(io IO) {
	io.StringLimits(&x.DataStoreName, 1, 1000)
	io.StringLimits(&x.Property, 1, 1000)
	io.StringLimits(&x.Path, 0, 1000)
	MarshalBedrockDDUIDataStoreUpdateData(io, &x.Data)
	io.Uint32(&x.PropertyUpdateCount)
	Maximum(io, &x.PropertyUpdateCount, 4.294967294e+09)
	io.Uint32(&x.PathUpdateCount)
	Maximum(io, &x.PathUpdateCount, 4.294967294e+09)
}

type BookEditActionAddPage struct {
	PageIndex int32
	PageText  string
	PhotoName string
}

func (*BookEditActionAddPage) tagBookEditAction() uint32 { return 1 }

// Marshal reads or writes BookEditActionAddPage using its canonical wire layout.
func (x *BookEditActionAddPage) Marshal(io IO) {
	io.Varint32(&x.PageIndex)
	io.StringLimits(&x.PageText, 0, 768)
	io.StringLimits(&x.PhotoName, 0, 768)
}

type BookEditActionDeletePage struct {
	PageIndex int32
}

func (*BookEditActionDeletePage) tagBookEditAction() uint32 { return 2 }

// Marshal reads or writes BookEditActionDeletePage using its canonical wire layout.
func (x *BookEditActionDeletePage) Marshal(io IO) {
	io.Varint32(&x.PageIndex)
}

type BookEditActionFinalize struct {
	Title  string
	Author string
	XUID   string
}

func (*BookEditActionFinalize) tagBookEditAction() uint32 { return 4 }

// Marshal reads or writes BookEditActionFinalize using its canonical wire layout.
func (x *BookEditActionFinalize) Marshal(io IO) {
	io.StringLimits(&x.Title, 0, 768)
	io.StringLimits(&x.Author, 0, 768)
	io.StringLimits(&x.XUID, 0, 768)
}

type BookEditActionReplacePage struct {
	PageIndex int32
	PageText  string
	PhotoName string
}

func (*BookEditActionReplacePage) tagBookEditAction() uint32 { return 0 }

// Marshal reads or writes BookEditActionReplacePage using its canonical wire layout.
func (x *BookEditActionReplacePage) Marshal(io IO) {
	io.Varint32(&x.PageIndex)
	io.StringLimits(&x.PageText, 0, 768)
	io.StringLimits(&x.PhotoName, 0, 768)
}

type BookEditActionSwapPages struct {
	PageIndex     int32
	SwapWithIndex int32
}

func (*BookEditActionSwapPages) tagBookEditAction() uint32 { return 3 }

// Marshal reads or writes BookEditActionSwapPages using its canonical wire layout.
func (x *BookEditActionSwapPages) Marshal(io IO) {
	io.Varint32(&x.PageIndex)
	io.Varint32(&x.SwapWithIndex)
}

type BossBarColor uint8

// Marshal reads or writes BossBarColor through its uint8 wire encoding.
func (x *BossBarColor) Marshal(io IO) { io.Uint8((*uint8)(x)) }

type BossBarOverlay uint8

// Marshal reads or writes BossBarOverlay through its uint8 wire encoding.
func (x *BossBarOverlay) Marshal(io IO) { io.Uint8((*uint8)(x)) }

type BossEventUpdateType uint8

// Marshal reads or writes BossEventUpdateType through its uint8 wire encoding.
func (x *BossEventUpdateType) Marshal(io IO) { io.Uint8((*uint8)(x)) }

type BoxData struct {
	BoxBound mgl32.Vec3
}

func (*BoxData) tagShape() uint32 { return 3 }

// Marshal reads or writes BoxData using its canonical wire layout.
func (x *BoxData) Marshal(io IO) {
	io.Vec3(&x.BoxBound)
}

type Cancel struct {
	ResponseType string
}

func (*Cancel) tagResourcePackClientResponseData() uint32 { return 0 }

// Marshal reads or writes Cancel using its canonical wire layout.
func (x *Cancel) Marshal(io IO) {
	io.String(&x.ResponseType)
}

type ChangeEntityScore struct {
	Action         string
	ScoreboardID   ScoreboardID
	ObjectiveName  string
	ScoreValue     int32
	EntityUniqueID int64
}

func (*ChangeEntityScore) tagSetScoreInfoItem() uint32 { return 2 }

// Marshal reads or writes ChangeEntityScore using its canonical wire layout.
func (x *ChangeEntityScore) Marshal(io IO) {
	io.String(&x.Action)
	x.ScoreboardID.Marshal(io)
	io.String(&x.ObjectiveName)
	io.Int32(&x.ScoreValue)
	io.ActorUniqueID(&x.EntityUniqueID)
}

type ChangeFakePlayerScore struct {
	Action         string
	ScoreboardID   ScoreboardID
	ObjectiveName  string
	ScoreValue     int32
	FakePlayerName string
}

func (*ChangeFakePlayerScore) tagSetScoreInfoItem() uint32 { return 3 }

// Marshal reads or writes ChangeFakePlayerScore using its canonical wire layout.
func (x *ChangeFakePlayerScore) Marshal(io IO) {
	io.String(&x.Action)
	x.ScoreboardID.Marshal(io)
	io.String(&x.ObjectiveName)
	io.Int32(&x.ScoreValue)
	io.String(&x.FakePlayerName)
}

type ChangePlayerScore struct {
	Action         string
	ScoreboardID   ScoreboardID
	ObjectiveName  string
	ScoreValue     int32
	PlayerUniqueID PlayerScoreboardID
}

func (*ChangePlayerScore) tagSetScoreInfoItem() uint32 { return 1 }

// Marshal reads or writes ChangePlayerScore using its canonical wire layout.
func (x *ChangePlayerScore) Marshal(io IO) {
	io.String(&x.Action)
	x.ScoreboardID.Marshal(io)
	io.String(&x.ObjectiveName)
	io.Int32(&x.ScoreValue)
	x.PlayerUniqueID.Marshal(io)
}

type ChatRestrictionLevel uint8

// Marshal reads or writes ChatRestrictionLevel through its uint8 wire encoding.
func (x *ChatRestrictionLevel) Marshal(io IO) { io.Uint8((*uint8)(x)) }

type ClearOverride struct {
	Type string
}

func (*ClearOverride) tagPlayerUpdateEntityOverridesData() uint32 { return 0 }

// Marshal reads or writes ClearOverride using its canonical wire layout.
func (x *ClearOverride) Marshal(io IO) {
	io.String(&x.Type)
}

type ClientCameraAimAssistAction uint8

// Marshal reads or writes ClientCameraAimAssistAction through its uint8 wire encoding.
func (x *ClientCameraAimAssistAction) Marshal(io IO) { io.Uint8((*uint8)(x)) }

type ClientPlayMode uint32

// Marshal reads or writes ClientPlayMode through its uint32 wire encoding.
func (x *ClientPlayMode) Marshal(io IO) { io.Varuint32((*uint32)(x)) }

type ClientboundTextureShiftAction uint8

// Marshal reads or writes ClientboundTextureShiftAction through its uint8 wire encoding.
func (x *ClientboundTextureShiftAction) Marshal(io IO) { io.Uint8((*uint8)(x)) }

type CodeBuilderExecutionStateCodeStatus uint8

// Marshal reads or writes CodeBuilderExecutionStateCodeStatus through its uint8 wire encoding.
func (x *CodeBuilderExecutionStateCodeStatus) Marshal(io IO) { io.Uint8((*uint8)(x)) }

type CodeBuilderStorageQueryOptionsCategory uint8

// Marshal reads or writes CodeBuilderStorageQueryOptionsCategory through its uint8 wire encoding.
func (x *CodeBuilderStorageQueryOptionsCategory) Marshal(io IO) { io.Uint8((*uint8)(x)) }

type CodeBuilderStorageQueryOptionsOperation uint8

// Marshal reads or writes CodeBuilderStorageQueryOptionsOperation through its uint8 wire encoding.
func (x *CodeBuilderStorageQueryOptionsOperation) Marshal(io IO) { io.Uint8((*uint8)(x)) }

type ConnectionDisconnectFailReason int32

// Marshal reads or writes ConnectionDisconnectFailReason through its int32 wire encoding.
func (x *ConnectionDisconnectFailReason) Marshal(io IO) { io.Varint32((*int32)(x)) }

type ContentIdentity struct {
	Identity string
}

// Marshal reads or writes ContentIdentity using its canonical wire layout.
func (x *ContentIdentity) Marshal(io IO) {
	io.String(&x.Identity)
}

type ControlScheme uint8

// Marshal reads or writes ControlScheme through its uint8 wire encoding.
func (x *ControlScheme) Marshal(io IO) { io.Uint8((*uint8)(x)) }

type CoordinatesLocation struct {
	PacketType PlayerLocationType
	Position   mgl32.Vec3
}

func (*CoordinatesLocation) tagPlayerLocationData() uint32 { return 0 }

// Marshal reads or writes CoordinatesLocation using its canonical wire layout.
func (x *CoordinatesLocation) Marshal(io IO) {
	x.PacketType.Marshal(io)
	io.Vec3(&x.Position)
}

type CraftLoomStackRequestAction struct {
	ActionType    ItemStackRequestActionType
	PatternNameID string
	NumCrafts     uint8
}

func (*CraftLoomStackRequestAction) tagStackRequestAction() uint32 { return 15 }

// Marshal reads or writes CraftLoomStackRequestAction using its canonical wire layout.
func (x *CraftLoomStackRequestAction) Marshal(io IO) {
	x.ActionType.Marshal(io)
	io.String(&x.PatternNameID)
	io.Uint8(&x.NumCrafts)
	Minimum(io, &x.NumCrafts, 1)
}

type CraftRepairAndDisenchantStackRequestAction struct {
	ActionType              ItemStackRequestActionType
	RecipeNetID             int32
	NumberOfRequestedCrafts uint8
	RepairCost              int32
}

func (*CraftRepairAndDisenchantStackRequestAction) tagStackRequestAction() uint32 { return 14 }

// Marshal reads or writes CraftRepairAndDisenchantStackRequestAction using its canonical wire layout.
func (x *CraftRepairAndDisenchantStackRequestAction) Marshal(io IO) {
	x.ActionType.Marshal(io)
	io.Int32(&x.RecipeNetID)
	io.Uint8(&x.NumberOfRequestedCrafts)
	Minimum(io, &x.NumberOfRequestedCrafts, 1)
	io.Varint32(&x.RepairCost)
	Minimum(io, &x.RepairCost, 0)
}

type DataItemByte struct {
	Type  DataItemType
	Value int8
}

func (*DataItemByte) tagDataItemEntryValue() uint32 { return 0 }

// Marshal reads or writes DataItemByte using its canonical wire layout.
func (x *DataItemByte) Marshal(io IO) {
	x.Type.Marshal(io)
	io.Int8(&x.Value)
}

type DataItemCompoundTag struct {
	Type  DataItemType
	Value []byte
}

func (*DataItemCompoundTag) tagDataItemEntryValue() uint32 { return 5 }

// Marshal reads or writes DataItemCompoundTag using its canonical wire layout.
func (x *DataItemCompoundTag) Marshal(io IO) {
	x.Type.Marshal(io)
	io.NBT(&x.Value, NBTNetwork)
}

type DataItemEntry struct {
	ID      uint32
	Payload DataItemEntryValue
}

// Marshal reads or writes DataItemEntry using its canonical wire layout.
func (x *DataItemEntry) Marshal(io IO) {
	io.Varuint32(&x.ID)
	MarshalDataItemEntryValue(io, &x.Payload)
}

type DataItemFloat struct {
	Type  DataItemType
	Value float32
}

func (*DataItemFloat) tagDataItemEntryValue() uint32 { return 3 }

// Marshal reads or writes DataItemFloat using its canonical wire layout.
func (x *DataItemFloat) Marshal(io IO) {
	x.Type.Marshal(io)
	io.Float32(&x.Value)
}

type DataItemInt struct {
	Type  DataItemType
	Value int32
}

func (*DataItemInt) tagDataItemEntryValue() uint32 { return 2 }

// Marshal reads or writes DataItemInt using its canonical wire layout.
func (x *DataItemInt) Marshal(io IO) {
	x.Type.Marshal(io)
	io.Varint32(&x.Value)
}

type DataItemInt64 struct {
	Type  DataItemType
	Value int64
}

func (*DataItemInt64) tagDataItemEntryValue() uint32 { return 7 }

// Marshal reads or writes DataItemInt64 using its canonical wire layout.
func (x *DataItemInt64) Marshal(io IO) {
	x.Type.Marshal(io)
	io.Varint64(&x.Value)
}

type DataItemPos struct {
	Type  DataItemType
	Value BlockPos
}

func (*DataItemPos) tagDataItemEntryValue() uint32 { return 6 }

// Marshal reads or writes DataItemPos using its canonical wire layout.
func (x *DataItemPos) Marshal(io IO) {
	x.Type.Marshal(io)
	x.Value.Marshal(io)
}

type DataItemShort struct {
	Type  DataItemType
	Value int16
}

func (*DataItemShort) tagDataItemEntryValue() uint32 { return 1 }

// Marshal reads or writes DataItemShort using its canonical wire layout.
func (x *DataItemShort) Marshal(io IO) {
	x.Type.Marshal(io)
	io.Int16(&x.Value)
}

type DataItemString struct {
	Type  DataItemType
	Value string
}

func (*DataItemString) tagDataItemEntryValue() uint32 { return 4 }

// Marshal reads or writes DataItemString using its canonical wire layout.
func (x *DataItemString) Marshal(io IO) {
	x.Type.Marshal(io)
	io.String(&x.Value)
}

type DataItemVec3 struct {
	Type  DataItemType
	Value mgl32.Vec3
}

func (*DataItemVec3) tagDataItemEntryValue() uint32 { return 8 }

// Marshal reads or writes DataItemVec3 using its canonical wire layout.
func (x *DataItemVec3) Marshal(io IO) {
	x.Type.Marshal(io)
	io.Vec3(&x.Value)
}

type DebugMarkerData struct {
	Text     string
	Position mgl32.Vec3
	Colour   color.RGBA
	Duration uint64
}

// Marshal reads or writes DebugMarkerData using its canonical wire layout.
func (x *DebugMarkerData) Marshal(io IO) {
	io.StringLimits(&x.Text, 0, 4096)
	io.Vec3(&x.Position)
	io.RGBA(&x.Colour)
	io.Uint64(&x.Duration)
}

type DimensionType struct {
	Value int32
}

// Marshal reads or writes DimensionType using its canonical wire layout.
func (x *DimensionType) Marshal(io IO) {
	io.Varint32(&x.Value)
}

type DisconnectMessagesData struct {
	Message         string
	FilteredMessage string
}

func (*DisconnectMessagesData) tagDisconnectMessages() uint32 { return 0 }

// Marshal reads or writes DisconnectMessagesData using its canonical wire layout.
func (x *DisconnectMessagesData) Marshal(io IO) {
	io.String(&x.Message)
	io.String(&x.FilteredMessage)
}

type Downloading struct {
	ResponseType     string
	DownloadingPacks []string
}

func (*Downloading) tagResourcePackClientResponseData() uint32 { return 1 }

// Marshal reads or writes Downloading using its canonical wire layout.
func (x *Downloading) Marshal(io IO) {
	io.String(&x.ResponseType)
	FuncSliceLimits(io, &x.DownloadingPacks, io.Varuint32, 0, 65535, io.String)
}

type DownloadingFinished struct {
	ResponseType string
}

func (*DownloadingFinished) tagResourcePackClientResponseData() uint32 { return 2 }

// Marshal reads or writes DownloadingFinished using its canonical wire layout.
func (x *DownloadingFinished) Marshal(io IO) {
	io.String(&x.ResponseType)
}

type DynamicValue interface {
	Marshaler
	tagDynamicValue() int32
}

// MarshalDynamicValue reads or writes the DynamicValue union using its canonical wire layout.
func MarshalDynamicValue(io IO, x *DynamicValue) {
	Union(io, x, io.Int32, DynamicValue.tagDynamicValue, func(tag int32) DynamicValue {
		switch tag {
		case 0:
			return new(DynamicValueNone)
		case 1:
			return new(DynamicValueBool)
		case 2:
			return new(DynamicValueInt64)
		case 3:
			return new(DynamicValueDouble)
		case 4:
			return new(DynamicValueString)
		case 5:
			return new(DynamicValueList)
		case 6:
			return new(DynamicValueMap)
		}
		return nil
	})
}

type EASAttributeLayerData struct {
	Name       string
	NoiseName  Optional[string]
	Dimension  DimensionType
	Settings   EASAttributeLayerSettings
	Attributes []EASEnvironmentAttributeData
}

// Marshal reads or writes EASAttributeLayerData using its canonical wire layout.
func (x *EASAttributeLayerData) Marshal(io IO) {
	io.StringLimits(&x.Name, 0, 128)
	OptionalFunc(io, &x.NoiseName, func(value *string) {
		io.StringLimits(value, 0, 128)
	})
	x.Dimension.Marshal(io)
	x.Settings.Marshal(io)
	SliceLimits(io, &x.Attributes, 0, 1024)
}

type EASAttributeLayerSettings struct {
	Priority          int32
	Weight            float32
	Enabled           bool
	TransitionsPaused bool
}

// Marshal reads or writes EASAttributeLayerSettings using its canonical wire layout.
func (x *EASAttributeLayerSettings) Marshal(io IO) {
	io.Int32(&x.Priority)
	io.Float32(&x.Weight)
	io.Bool(&x.Enabled)
	io.Bool(&x.TransitionsPaused)
}

type EASBoolAttributeData struct {
	Value     bool
	Operation string
}

func (*EASBoolAttributeData) tagEAS() uint32 { return 0 }

// Marshal reads or writes EASBoolAttributeData using its canonical wire layout.
func (x *EASBoolAttributeData) Marshal(io IO) {
	io.Bool(&x.Value)
	io.String(&x.Operation)
}

type EASColorAttributeData struct {
	Value     [4]int32
	Operation string
}

func (*EASColorAttributeData) tagEAS() uint32 { return 2 }

// Marshal reads or writes EASColorAttributeData using its canonical wire layout.
func (x *EASColorAttributeData) Marshal(io IO) {
	for index1 := range x.Value {
		io.Int32(&x.Value[index1])
	}
	io.String(&x.Operation)
}

type EASEnvironmentAttributeData struct {
	AttributeName          string
	FromAttribute          Optional[EAS]
	Attribute              EAS
	ToAttribute            Optional[EAS]
	CurrentTransitionTicks uint32
	TotalTransitionTicks   uint32
	Easing                 string
	LocalTransitionTicks   uint32
	NoiseTransition        bool
	NoiseAlignment         NoiseAlignment
}

// Marshal reads or writes EASEnvironmentAttributeData using its canonical wire layout.
func (x *EASEnvironmentAttributeData) Marshal(io IO) {
	io.StringLimits(&x.AttributeName, 0, 128)
	OptionalFunc(io, &x.FromAttribute, func(value *EAS) {
		MarshalEAS(io, value)
	})
	MarshalEAS(io, &x.Attribute)
	OptionalFunc(io, &x.ToAttribute, func(value *EAS) {
		MarshalEAS(io, value)
	})
	io.Uint32(&x.CurrentTransitionTicks)
	io.Uint32(&x.TotalTransitionTicks)
	io.String(&x.Easing)
	io.Uint32(&x.LocalTransitionTicks)
	io.Bool(&x.NoiseTransition)
	x.NoiseAlignment.Marshal(io)
}

type EASFloatAttributeData struct {
	Value         float32
	Operation     string
	ConstraintMin Optional[float32]
	ConstraintMax Optional[float32]
}

func (*EASFloatAttributeData) tagEAS() uint32 { return 1 }

// Marshal reads or writes EASFloatAttributeData using its canonical wire layout.
func (x *EASFloatAttributeData) Marshal(io IO) {
	io.Float32(&x.Value)
	io.String(&x.Operation)
	OptionalFunc(io, &x.ConstraintMin, io.Float32)
	OptionalFunc(io, &x.ConstraintMax, io.Float32)
}

type EditorWorldType int32

// Marshal reads or writes EditorWorldType through its int32 wire encoding.
func (x *EditorWorldType) Marshal(io IO) { io.Varint32((*int32)(x)) }

type Empty struct {
}

func (*Empty) tagEventData() uint32 { return 21 }

// Marshal reads or writes Empty using its canonical wire layout.
func (x *Empty) Marshal(io IO) {
}

type Experiments struct {
	Toggles                []ExperimentData
	ExperimentsEverToggled bool
}

// Marshal reads or writes Experiments using its canonical wire layout.
func (x *Experiments) Marshal(io IO) {
	FuncSlice(io, &x.Toggles, io.Uint32, func(value *ExperimentData) {
		value.Marshal(io)
	})
	io.Bool(&x.ExperimentsEverToggled)
}

type FeatureRegistryFeatureBinaryJSONFormat struct {
	FeatureName      string
	BinaryJSONOutput []byte
}

// Marshal reads or writes FeatureRegistryFeatureBinaryJSONFormat using its canonical wire layout.
func (x *FeatureRegistryFeatureBinaryJSONFormat) Marshal(io IO) {
	io.String(&x.FeatureName)
	io.ByteSlice(&x.BinaryJSONOutput)
}

type FloatOverride struct {
	Type  string
	Value float32
}

func (*FloatOverride) tagPlayerUpdateEntityOverridesData() uint32 { return 3 }

// Marshal reads or writes FloatOverride using its canonical wire layout.
func (x *FloatOverride) Marshal(io IO) {
	io.String(&x.Type)
	io.Float32(&x.Value)
}

type GameRulesChangedData struct {
	RulesList []GameRule
}

// Marshal reads or writes GameRulesChangedData using its canonical wire layout.
func (x *GameRulesChangedData) Marshal(io IO) {
	Slice(io, &x.RulesList)
}

type GameType int32

// Marshal reads or writes GameType through its int32 wire encoding.
func (x *GameType) Marshal(io IO) { io.Varint32((*int32)(x)) }

type GraphicsMode uint8

// Marshal reads or writes GraphicsMode through its uint8 wire encoding.
func (x *GraphicsMode) Marshal(io IO) { io.Uint8((*uint8)(x)) }

type HeightmapData struct {
	HeightMapType           HeightMapDataType
	SubchunkHeightMap       Optional[[16][]int8]
	RenderHeightMapType     HeightMapDataType
	SubchunkRenderHeightMap Optional[[16][]int8]
}

// Marshal reads or writes HeightmapData using its canonical wire layout.
func (x *HeightmapData) Marshal(io IO) {
	x.HeightMapType.Marshal(io)
	OptionalFunc(io, &x.SubchunkHeightMap, func(value *[16][]int8) {
		for index1 := range *value {
			FuncSlice(io, &(*value)[index1], io.Varuint32, io.Int8)
		}
	})
	x.RenderHeightMapType.Marshal(io)
	OptionalFunc(io, &x.SubchunkRenderHeightMap, func(value *[16][]int8) {
		for index2 := range *value {
			FuncSlice(io, &(*value)[index2], io.Varuint32, io.Int8)
		}
	})
}

type HiddenLocation struct {
	PacketType PlayerLocationType
}

func (*HiddenLocation) tagPlayerLocationData() uint32 { return 1 }

// Marshal reads or writes HiddenLocation using its canonical wire layout.
func (x *HiddenLocation) Marshal(io IO) {
	x.PacketType.Marshal(io)
}

type HudElement int32

// Marshal reads or writes HudElement through its int32 wire encoding.
func (x *HudElement) Marshal(io IO) { io.Varint32((*int32)(x)) }

type HudVisibility int32

// Marshal reads or writes HudVisibility through its int32 wire encoding.
func (x *HudVisibility) Marshal(io IO) { io.Varint32((*int32)(x)) }

type InitializeRegistryData struct {
	ClockData []WorldClockData
}

func (*InitializeRegistryData) tagSyncWorldClocksData() uint32 { return 1 }

// Marshal reads or writes InitializeRegistryData using its canonical wire layout.
func (x *InitializeRegistryData) Marshal(io IO) {
	SliceLimits(io, &x.ClockData, 0, 256)
}

type InputData int32

// Marshal reads or writes InputData through its int32 wire encoding.
func (x *InputData) Marshal(io IO) { io.Varint32((*int32)(x)) }

type InputMode uint32

// Marshal reads or writes InputMode through its uint32 wire encoding.
func (x *InputMode) Marshal(io IO) { io.Varuint32((*uint32)(x)) }

type IntOverride struct {
	Type  string
	Value int32
}

func (*IntOverride) tagPlayerUpdateEntityOverridesData() uint32 { return 2 }

// Marshal reads or writes IntOverride using its canonical wire layout.
func (x *IntOverride) Marshal(io IO) {
	io.String(&x.Type)
	io.Int32(&x.Value)
}

type InteractAction uint8

// Marshal reads or writes InteractAction through its uint8 wire encoding.
func (x *InteractAction) Marshal(io IO) { io.Uint8((*uint8)(x)) }

type Interaction struct {
	InteractedEntityID       int64
	InteractionType          MinecraftEventingInteractionType
	InteractionEntityType    int32
	InteractionEntityVariant int32
	InteractionEntityColour  uint8
}

func (*Interaction) tagEventData() uint32 { return 1 }

// Marshal reads or writes Interaction using its canonical wire layout.
func (x *Interaction) Marshal(io IO) {
	io.Varint64(&x.InteractedEntityID)
	x.InteractionType.Marshal(io)
	io.Varint32(&x.InteractionEntityType)
	io.Varint32(&x.InteractionEntityVariant)
	io.Uint8(&x.InteractionEntityColour)
}

type LabTableReactionType uint8

const (
	LabTableReactionTypeNone               LabTableReactionType = 0
	LabTableReactionTypeIcebomb            LabTableReactionType = 1
	LabTableReactionTypeBleach             LabTableReactionType = 2
	LabTableReactionTypeElephanttoothpaste LabTableReactionType = 3
	LabTableReactionTypeFertilizer         LabTableReactionType = 4
	LabTableReactionTypeHeatblock          LabTableReactionType = 5
	LabTableReactionTypeMagnesiumsalts     LabTableReactionType = 6
	LabTableReactionTypeMiscfire           LabTableReactionType = 7
	LabTableReactionTypeMiscexplosion      LabTableReactionType = 8
	LabTableReactionTypeMisclava           LabTableReactionType = 9
	LabTableReactionTypeMiscmystical       LabTableReactionType = 10
	LabTableReactionTypeMiscsmoke          LabTableReactionType = 11
	LabTableReactionTypeMisclargesmoke     LabTableReactionType = 12
)

// Marshal reads or writes LabTableReactionType through its uint8 wire encoding.
func (x *LabTableReactionType) Marshal(io IO) { io.Uint8((*uint8)(x)) }

type LabTableType uint8

// Marshal reads or writes LabTableType through its uint8 wire encoding.
func (x *LabTableType) Marshal(io IO) { io.Uint8((*uint8)(x)) }

type LegacyArmorSlot int32

// Marshal reads or writes LegacyArmorSlot through its int32 wire encoding.
func (x *LegacyArmorSlot) Marshal(io IO) { io.Varint32((*int32)(x)) }

type LegacyDifficulty int32

const (
	LegacyDifficultyPeaceful LegacyDifficulty = 0
	LegacyDifficultyEasy     LegacyDifficulty = 1
	LegacyDifficultyNormal   LegacyDifficulty = 2
	LegacyDifficultyHard     LegacyDifficulty = 3
	LegacyDifficultyCount    LegacyDifficulty = 4
	LegacyDifficultyUnknown  LegacyDifficulty = 5
)

// Marshal reads or writes LegacyDifficulty through its int32 wire encoding.
func (x *LegacyDifficulty) Marshal(io IO) { io.Varint32((*int32)(x)) }

type LegacySetSlot struct {
	ContainerEnum ContainerEnumName
	Slots         []uint8
}

// Marshal reads or writes LegacySetSlot using its canonical wire layout.
func (x *LegacySetSlot) Marshal(io IO) {
	x.ContainerEnum.Marshal(io)
	FuncSlice(io, &x.Slots, io.Varuint32, io.Uint8)
}

type LevelSettings struct {
	Seed                                   uint64
	SpawnSettings                          SpawnSettings
	GeneratorType                          GeneratorType
	GameType                               GameType
	IsHardcore                             bool
	GameDifficulty                         LegacyDifficulty
	DefaultSpawnBlockPosition              BlockPos
	AchievementsDisabled                   bool
	EditorWorldType                        EditorWorldType
	IsCreatedInEditor                      bool
	IsExportedFromEditor                   bool
	DayCycleStopTime                       int32
	EducationEditionOffer                  EducationEditionOffer
	EducationFeaturesEnabled               bool
	EducationProductID                     string
	RainLevel                              float32
	LightningLevel                         float32
	HasConfirmedPlatformLockedContent      bool
	MultiplayerGameIntent                  bool
	LANBroadcastIntent                     bool
	XboxLiveBroadcastSetting               SocialGamePublishSetting
	PlatformBroadcastSetting               SocialGamePublishSetting
	CommandsEnabled                        bool
	TexturePacksRequired                   bool
	RuleData                               GameRulesChangedData
	Experiments                            Experiments
	HasBonusChestEnabled                   bool
	StartWithMapEnabled                    bool
	PlayerPermissions                      PlayerPermissionLevel
	ServerChunkTickRange                   int32
	HasLockedBehaviourPack                 bool
	HasLockedResourcePack                  bool
	IsFromLockedTemplate                   bool
	UseMsaGamertagsOnly                    bool
	IsFromWorldTemplate                    bool
	IsWorldTemplateOptionLocked            bool
	OnlySpawnV1Villagers                   bool
	PersonaDisabled                        bool
	CustomSkinsDisabled                    bool
	EmoteChatMuted                         bool
	BaseGameVersion                        string
	LimitedWorldWidth                      int32
	LimitedWorldDepth                      int32
	NetherType                             bool
	EduSharedURIResource                   EducationSharedResourceURI
	OverrideForceExperimentalGameplay      Optional[bool]
	ChatRestrictionLevel                   ChatRestrictionLevel
	DisablePlayerInteractions              bool
	ServerEditorConnectionPolicy           ServerEditorConnectionPolicy
	AllowAnonymousBlockDropsInEditorWorlds bool
}

// Marshal reads or writes LevelSettings using its canonical wire layout.
func (x *LevelSettings) Marshal(io IO) {
	io.Uint64(&x.Seed)
	x.SpawnSettings.Marshal(io)
	x.GeneratorType.Marshal(io)
	x.GameType.Marshal(io)
	io.Bool(&x.IsHardcore)
	x.GameDifficulty.Marshal(io)
	x.DefaultSpawnBlockPosition.Marshal(io)
	io.Bool(&x.AchievementsDisabled)
	x.EditorWorldType.Marshal(io)
	io.Bool(&x.IsCreatedInEditor)
	io.Bool(&x.IsExportedFromEditor)
	io.Varint32(&x.DayCycleStopTime)
	x.EducationEditionOffer.Marshal(io)
	io.Bool(&x.EducationFeaturesEnabled)
	io.String(&x.EducationProductID)
	io.Float32(&x.RainLevel)
	io.Float32(&x.LightningLevel)
	io.Bool(&x.HasConfirmedPlatformLockedContent)
	io.Bool(&x.MultiplayerGameIntent)
	io.Bool(&x.LANBroadcastIntent)
	x.XboxLiveBroadcastSetting.Marshal(io)
	x.PlatformBroadcastSetting.Marshal(io)
	io.Bool(&x.CommandsEnabled)
	io.Bool(&x.TexturePacksRequired)
	x.RuleData.Marshal(io)
	x.Experiments.Marshal(io)
	io.Bool(&x.HasBonusChestEnabled)
	io.Bool(&x.StartWithMapEnabled)
	x.PlayerPermissions.Marshal(io)
	io.Int32(&x.ServerChunkTickRange)
	io.Bool(&x.HasLockedBehaviourPack)
	io.Bool(&x.HasLockedResourcePack)
	io.Bool(&x.IsFromLockedTemplate)
	io.Bool(&x.UseMsaGamertagsOnly)
	io.Bool(&x.IsFromWorldTemplate)
	io.Bool(&x.IsWorldTemplateOptionLocked)
	io.Bool(&x.OnlySpawnV1Villagers)
	io.Bool(&x.PersonaDisabled)
	io.Bool(&x.CustomSkinsDisabled)
	io.Bool(&x.EmoteChatMuted)
	io.String(&x.BaseGameVersion)
	io.Int32(&x.LimitedWorldWidth)
	io.Int32(&x.LimitedWorldDepth)
	io.Bool(&x.NetherType)
	x.EduSharedURIResource.Marshal(io)
	OptionalFunc(io, &x.OverrideForceExperimentalGameplay, io.Bool)
	x.ChatRestrictionLevel.Marshal(io)
	io.Bool(&x.DisablePlayerInteractions)
	x.ServerEditorConnectionPolicy.Marshal(io)
	io.Bool(&x.AllowAnonymousBlockDropsInEditorWorlds)
}

type LineData struct {
	LineEndLocation mgl32.Vec3
}

func (*LineData) tagShape() uint32 { return 4 }

// Marshal reads or writes LineData using its canonical wire layout.
func (x *LineData) Marshal(io IO) {
	io.Vec3(&x.LineEndLocation)
}

type MaterialReducerDataEntry struct {
	FromItemKey      int32
	ItemIdsAndCounts []MaterialReducerEntryOutput
}

// Marshal reads or writes MaterialReducerDataEntry using its canonical wire layout.
func (x *MaterialReducerDataEntry) Marshal(io IO) {
	io.Varint32(&x.FromItemKey)
	Slice(io, &x.ItemIdsAndCounts)
}

type MaterialReducerEntryOutput struct {
	ItemID    int32
	ItemCount int32
}

// Marshal reads or writes MaterialReducerEntryOutput using its canonical wire layout.
func (x *MaterialReducerEntryOutput) Marshal(io IO) {
	io.Varint32(&x.ItemID)
	io.Varint32(&x.ItemCount)
}

type MessageAndParams struct {
	MessageType   TextPacketType
	Message       string
	ParameterList []string
}

func (*MessageAndParams) tagTextData() uint32 { return 2 }

// Marshal reads or writes MessageAndParams using its canonical wire layout.
func (x *MessageAndParams) Marshal(io IO) {
	x.MessageType.Marshal(io)
	io.StringLimits(&x.Message, 1, 65536)
	FuncSliceLimits(io, &x.ParameterList, io.Varuint32, 0, 4, io.String)
}

type MessageOnly struct {
	MessageType TextPacketType
	Message     string
}

func (*MessageOnly) tagTextData() uint32 { return 0 }

// Marshal reads or writes MessageOnly using its canonical wire layout.
func (x *MessageOnly) Marshal(io IO) {
	x.MessageType.Marshal(io)
	io.StringLimits(&x.Message, 1, 65536)
}

type MinecraftEventingAchievementIds uint8

const (
	MinecraftEventingAchievementIdsChestfullofcobblestone          MinecraftEventingAchievementIds = 7
	MinecraftEventingAchievementIdsDiamondforyou                   MinecraftEventingAchievementIds = 10
	MinecraftEventingAchievementIdsIronbelly                       MinecraftEventingAchievementIds = 20
	MinecraftEventingAchievementIdsIronman                         MinecraftEventingAchievementIds = 21
	MinecraftEventingAchievementIdsOnarail                         MinecraftEventingAchievementIds = 29
	MinecraftEventingAchievementIdsOverkill                        MinecraftEventingAchievementIds = 30
	MinecraftEventingAchievementIdsReturntosender                  MinecraftEventingAchievementIds = 37
	MinecraftEventingAchievementIdsSniperduel                      MinecraftEventingAchievementIds = 38
	MinecraftEventingAchievementIdsStayinfrosty                    MinecraftEventingAchievementIds = 39
	MinecraftEventingAchievementIdsTakeinventory                   MinecraftEventingAchievementIds = 40
	MinecraftEventingAchievementIdsMaproom                         MinecraftEventingAchievementIds = 50
	MinecraftEventingAchievementIdsFreightstation                  MinecraftEventingAchievementIds = 52
	MinecraftEventingAchievementIdsSmelteverything                 MinecraftEventingAchievementIds = 53
	MinecraftEventingAchievementIdsTasteofyourownmedicine          MinecraftEventingAchievementIds = 54
	MinecraftEventingAchievementIdsWhenpigsfly                     MinecraftEventingAchievementIds = 56
	MinecraftEventingAchievementIdsInception                       MinecraftEventingAchievementIds = 58
	MinecraftEventingAchievementIdsArtificialselection             MinecraftEventingAchievementIds = 60
	MinecraftEventingAchievementIdsFreediver                       MinecraftEventingAchievementIds = 61
	MinecraftEventingAchievementIdsSpawnthewither                  MinecraftEventingAchievementIds = 62
	MinecraftEventingAchievementIdsBeaconator                      MinecraftEventingAchievementIds = 63
	MinecraftEventingAchievementIdsGreatview                       MinecraftEventingAchievementIds = 64
	MinecraftEventingAchievementIdsSupersonic                      MinecraftEventingAchievementIds = 65
	MinecraftEventingAchievementIdsTheendagain                     MinecraftEventingAchievementIds = 66
	MinecraftEventingAchievementIdsTreasurehunter                  MinecraftEventingAchievementIds = 67
	MinecraftEventingAchievementIdsShootingstar                    MinecraftEventingAchievementIds = 68
	MinecraftEventingAchievementIdsFashionshow                     MinecraftEventingAchievementIds = 69
	MinecraftEventingAchievementIdsSelfpublishedauthor             MinecraftEventingAchievementIds = 71
	MinecraftEventingAchievementIdsAlternativefuel                 MinecraftEventingAchievementIds = 72
	MinecraftEventingAchievementIdsSleepwiththefishes              MinecraftEventingAchievementIds = 73
	MinecraftEventingAchievementIdsCastaway                        MinecraftEventingAchievementIds = 74
	MinecraftEventingAchievementIdsImamarinebiologist              MinecraftEventingAchievementIds = 75
	MinecraftEventingAchievementIdsSailthe7seas                    MinecraftEventingAchievementIds = 76
	MinecraftEventingAchievementIdsMegold                          MinecraftEventingAchievementIds = 77
	MinecraftEventingAchievementIdsAhoy                            MinecraftEventingAchievementIds = 78
	MinecraftEventingAchievementIdsAtlantis                        MinecraftEventingAchievementIds = 79
	MinecraftEventingAchievementIdsOnepickletwopickleseapicklefour MinecraftEventingAchievementIds = 80
	MinecraftEventingAchievementIdsDoabarrelroll                   MinecraftEventingAchievementIds = 81
	MinecraftEventingAchievementIdsMoskstraumen                    MinecraftEventingAchievementIds = 82
	MinecraftEventingAchievementIdsEcholocation                    MinecraftEventingAchievementIds = 83
	MinecraftEventingAchievementIdsWherehaveyoubeen                MinecraftEventingAchievementIds = 84
	MinecraftEventingAchievementIdsTopoftheworld                   MinecraftEventingAchievementIds = 85
	MinecraftEventingAchievementIdsFruitontheloom                  MinecraftEventingAchievementIds = 86
	MinecraftEventingAchievementIdsSoundthealarm                   MinecraftEventingAchievementIds = 87
	MinecraftEventingAchievementIdsBuylowsellhigh                  MinecraftEventingAchievementIds = 88
	MinecraftEventingAchievementIdsDisenchanted                    MinecraftEventingAchievementIds = 89
	MinecraftEventingAchievementIdsTimeforstew                     MinecraftEventingAchievementIds = 90
	MinecraftEventingAchievementIdsBeeourguest                     MinecraftEventingAchievementIds = 91
	MinecraftEventingAchievementIdsTotalbeelocation                MinecraftEventingAchievementIds = 92
	MinecraftEventingAchievementIdsStickysituation                 MinecraftEventingAchievementIds = 93
	MinecraftEventingAchievementIdsCovermeindebris                 MinecraftEventingAchievementIds = 94
	MinecraftEventingAchievementIdsFloatyourgoat                   MinecraftEventingAchievementIds = 95
	MinecraftEventingAchievementIdsFriend                          MinecraftEventingAchievementIds = 96
	MinecraftEventingAchievementIdsWaxonwaxoff                     MinecraftEventingAchievementIds = 97
	MinecraftEventingAchievementIdsStriderriddeninlavainoverworld  MinecraftEventingAchievementIds = 98
	MinecraftEventingAchievementIdsGoathornacquired                MinecraftEventingAchievementIds = 99
	MinecraftEventingAchievementIdsJukeboxusedinmeadows            MinecraftEventingAchievementIds = 100
	MinecraftEventingAchievementIdsTradedatworldheight             MinecraftEventingAchievementIds = 101
	MinecraftEventingAchievementIdsSurvivedfallfromworldheight     MinecraftEventingAchievementIds = 102
	MinecraftEventingAchievementIdsSneakclosetosculksensor         MinecraftEventingAchievementIds = 103
	MinecraftEventingAchievementIdsItspreads                       MinecraftEventingAchievementIds = 104
	MinecraftEventingAchievementIdsBirthdaysong                    MinecraftEventingAchievementIds = 105
	MinecraftEventingAchievementIdsWithourpowerscombined           MinecraftEventingAchievementIds = 106
	MinecraftEventingAchievementIdsPlantingthepast                 MinecraftEventingAchievementIds = 107
	MinecraftEventingAchievementIdsCarefulrestoration              MinecraftEventingAchievementIds = 108
	MinecraftEventingAchievementIdsRevaulting                      MinecraftEventingAchievementIds = 109
	MinecraftEventingAchievementIdsCrafterscraftingcrafters        MinecraftEventingAchievementIds = 110
	MinecraftEventingAchievementIdsWhoneedsrockets                 MinecraftEventingAchievementIds = 111
	MinecraftEventingAchievementIdsOveroverkill                    MinecraftEventingAchievementIds = 112
	MinecraftEventingAchievementIdsHearttransplanter               MinecraftEventingAchievementIds = 113
	MinecraftEventingAchievementIdsStayhydrated                    MinecraftEventingAchievementIds = 114
	MinecraftEventingAchievementIdsMobkabob                        MinecraftEventingAchievementIds = 115
	MinecraftEventingAchievementIdsAdventuringtime                 MinecraftEventingAchievementIds = 116
	MinecraftEventingAchievementIdsUhoh                            MinecraftEventingAchievementIds = 117
	MinecraftEventingAchievementIdsGettingwood                     MinecraftEventingAchievementIds = 118
	MinecraftEventingAchievementIdsBenchmaking                     MinecraftEventingAchievementIds = 119
	MinecraftEventingAchievementIdsTimetomine                      MinecraftEventingAchievementIds = 120
	MinecraftEventingAchievementIdsHottopic                        MinecraftEventingAchievementIds = 121
	MinecraftEventingAchievementIdsAcquirehardware                 MinecraftEventingAchievementIds = 122
	MinecraftEventingAchievementIdsGettinganupgrade                MinecraftEventingAchievementIds = 123
	MinecraftEventingAchievementIdsMonsterhunter                   MinecraftEventingAchievementIds = 124
	MinecraftEventingAchievementIdsDiamonds                        MinecraftEventingAchievementIds = 125
	MinecraftEventingAchievementIdsPlethoraofcats                  MinecraftEventingAchievementIds = 126
)

// Marshal reads or writes MinecraftEventingAchievementIds through its uint8 wire encoding.
func (x *MinecraftEventingAchievementIds) Marshal(io IO) { io.Uint8((*uint8)(x)) }

type MinecraftEventingInteractionType uint8

const (
	MinecraftEventingInteractionTypeBreeding   MinecraftEventingInteractionType = 1
	MinecraftEventingInteractionTypeTaming     MinecraftEventingInteractionType = 2
	MinecraftEventingInteractionTypeCuring     MinecraftEventingInteractionType = 3
	MinecraftEventingInteractionTypeCrafted    MinecraftEventingInteractionType = 4
	MinecraftEventingInteractionTypeShearing   MinecraftEventingInteractionType = 5
	MinecraftEventingInteractionTypeMilking    MinecraftEventingInteractionType = 6
	MinecraftEventingInteractionTypeTrading    MinecraftEventingInteractionType = 7
	MinecraftEventingInteractionTypeFeeding    MinecraftEventingInteractionType = 8
	MinecraftEventingInteractionTypeIgniting   MinecraftEventingInteractionType = 9
	MinecraftEventingInteractionTypeColoring   MinecraftEventingInteractionType = 10
	MinecraftEventingInteractionTypeNaming     MinecraftEventingInteractionType = 11
	MinecraftEventingInteractionTypeLeashing   MinecraftEventingInteractionType = 12
	MinecraftEventingInteractionTypeUnleashing MinecraftEventingInteractionType = 13
	MinecraftEventingInteractionTypePetsleep   MinecraftEventingInteractionType = 14
	MinecraftEventingInteractionTypeTrusting   MinecraftEventingInteractionType = 15
	MinecraftEventingInteractionTypeCommanding MinecraftEventingInteractionType = 16
	MinecraftEventingInteractionTypeEquipping  MinecraftEventingInteractionType = 17
)

// Marshal reads or writes MinecraftEventingInteractionType through its uint8 wire encoding.
func (x *MinecraftEventingInteractionType) Marshal(io IO) { io.Uint8((*uint8)(x)) }

type MinecraftEventingPOIBlockInteractionType uint8

const (
	MinecraftEventingPOIBlockInteractionTypeNone                MinecraftEventingPOIBlockInteractionType = 0
	MinecraftEventingPOIBlockInteractionTypeExtend              MinecraftEventingPOIBlockInteractionType = 1
	MinecraftEventingPOIBlockInteractionTypeClone               MinecraftEventingPOIBlockInteractionType = 2
	MinecraftEventingPOIBlockInteractionTypeLock                MinecraftEventingPOIBlockInteractionType = 3
	MinecraftEventingPOIBlockInteractionTypeCreate              MinecraftEventingPOIBlockInteractionType = 4
	MinecraftEventingPOIBlockInteractionTypeCreatelocator       MinecraftEventingPOIBlockInteractionType = 5
	MinecraftEventingPOIBlockInteractionTypeRename              MinecraftEventingPOIBlockInteractionType = 6
	MinecraftEventingPOIBlockInteractionTypeItemplaced          MinecraftEventingPOIBlockInteractionType = 7
	MinecraftEventingPOIBlockInteractionTypeItemremoved         MinecraftEventingPOIBlockInteractionType = 8
	MinecraftEventingPOIBlockInteractionTypeCooking             MinecraftEventingPOIBlockInteractionType = 9
	MinecraftEventingPOIBlockInteractionTypeDousing             MinecraftEventingPOIBlockInteractionType = 10
	MinecraftEventingPOIBlockInteractionTypeLighting            MinecraftEventingPOIBlockInteractionType = 11
	MinecraftEventingPOIBlockInteractionTypeHaystack            MinecraftEventingPOIBlockInteractionType = 12
	MinecraftEventingPOIBlockInteractionTypeFilled              MinecraftEventingPOIBlockInteractionType = 13
	MinecraftEventingPOIBlockInteractionTypeEmptied             MinecraftEventingPOIBlockInteractionType = 14
	MinecraftEventingPOIBlockInteractionTypeAdddye              MinecraftEventingPOIBlockInteractionType = 15
	MinecraftEventingPOIBlockInteractionTypeDyeitem             MinecraftEventingPOIBlockInteractionType = 16
	MinecraftEventingPOIBlockInteractionTypeClearitem           MinecraftEventingPOIBlockInteractionType = 17
	MinecraftEventingPOIBlockInteractionTypeEnchantarrow        MinecraftEventingPOIBlockInteractionType = 18
	MinecraftEventingPOIBlockInteractionTypeCompostitemplaced   MinecraftEventingPOIBlockInteractionType = 19
	MinecraftEventingPOIBlockInteractionTypeRecoveredbonemeal   MinecraftEventingPOIBlockInteractionType = 20
	MinecraftEventingPOIBlockInteractionTypeBookplaced          MinecraftEventingPOIBlockInteractionType = 21
	MinecraftEventingPOIBlockInteractionTypeBookopened          MinecraftEventingPOIBlockInteractionType = 22
	MinecraftEventingPOIBlockInteractionTypeDisenchant          MinecraftEventingPOIBlockInteractionType = 23
	MinecraftEventingPOIBlockInteractionTypeRepair              MinecraftEventingPOIBlockInteractionType = 24
	MinecraftEventingPOIBlockInteractionTypeDisenchantandrepair MinecraftEventingPOIBlockInteractionType = 25
)

// Marshal reads or writes MinecraftEventingPOIBlockInteractionType through its uint8 wire encoding.
func (x *MinecraftEventingPOIBlockInteractionType) Marshal(io IO) { io.Uint8((*uint8)(x)) }

type MissingBlobData struct {
	BlobID   uint64
	BlobData []byte
}

// Marshal reads or writes MissingBlobData using its canonical wire layout.
func (x *MissingBlobData) Marshal(io IO) {
	io.Uint64(&x.BlobID)
	io.ByteSlice(&x.BlobData)
}

type MoLangVersion int16

const (
	MoLangVersionInvalid                                MoLangVersion = -1
	MoLangVersionBeforeversioning                       MoLangVersion = 0
	MoLangVersionInitial                                MoLangVersion = 1
	MoLangVersionFixeditemremainingusedurationquery     MoLangVersion = 2
	MoLangVersionExpressionerrormessages                MoLangVersion = 3
	MoLangVersionUnexpectedoperatorerrors               MoLangVersion = 4
	MoLangVersionConditionaloperatorassociativity       MoLangVersion = 5
	MoLangVersionComparisonandlogicaloperatorprecedence MoLangVersion = 6
	MoLangVersionDividebynegativevalue                  MoLangVersion = 7
	MoLangVersionFixedcapeflapamountquery               MoLangVersion = 8
	MoLangVersionQueryblockpropertyrenamedtostate       MoLangVersion = 9
	MoLangVersionDeprecateoldblockquerynames            MoLangVersion = 10
	MoLangVersionDeprecatedsnifferandcamelqueries       MoLangVersion = 11
	MoLangVersionLeafsupportinginfirstsolidblockbelow   MoLangVersion = 12
	MoLangVersionLatest                                 MoLangVersion = 13
	MoLangVersionNumvalidversions                       MoLangVersion = 14
)

// Marshal reads or writes MoLangVersion through its int16 wire encoding.
func (x *MoLangVersion) Marshal(io IO) { io.Int16((*int16)(x)) }

type MobEffectEvent uint8

// Marshal reads or writes MobEffectEvent through its uint8 wire encoding.
func (x *MobEffectEvent) Marshal(io IO) { io.Uint8((*uint8)(x)) }

type ModalFormCancelReason uint8

// Marshal reads or writes ModalFormCancelReason through its uint8 wire encoding.
func (x *ModalFormCancelReason) Marshal(io IO) { io.Uint8((*uint8)(x)) }

type MovePlayerTeleportData struct {
	TeleportationCause int32
	SourceEntityType   int32
}

// Marshal reads or writes MovePlayerTeleportData using its canonical wire layout.
func (x *MovePlayerTeleportData) Marshal(io IO) {
	io.Int32(&x.TeleportationCause)
	io.Int32(&x.SourceEntityType)
}

type MovementEffectType int32

// Marshal reads or writes MovementEffectType through its int32 wire encoding.
func (x *MovementEffectType) Marshal(io IO) { io.Varint32((*int32)(x)) }

type MultiplayerSettingsType int32

// Marshal reads or writes MultiplayerSettingsType through its int32 wire encoding.
func (x *MultiplayerSettingsType) Marshal(io IO) { io.Varint32((*int32)(x)) }

type NetworkItemInstanceDescriptorSerializedData struct {
	ID             int32
	StackSize      uint16
	AuxValue       uint32
	BlockRuntimeID int32
	UserDataBuffer []byte
}

// Marshal reads or writes NetworkItemInstanceDescriptorSerializedData using its canonical wire layout.
func (x *NetworkItemInstanceDescriptorSerializedData) Marshal(io IO) {
	io.Varint32(&x.ID)
	Minimum(io, &x.ID, -32768)
	Maximum(io, &x.ID, 32767)
	io.Uint16(&x.StackSize)
	io.Varuint32(&x.AuxValue)
	Maximum(io, &x.AuxValue, 32767)
	io.Varint32(&x.BlockRuntimeID)
	io.ByteSlice(&x.UserDataBuffer)
}

type NetworkItemStackDescriptorSerializedData struct {
	ID             int16
	StackSize      uint16
	AuxValue       uint32
	NetIDVariant   Optional[int32]
	BlockRuntimeID uint32
	UserDataBuffer []byte
}

// Marshal reads or writes NetworkItemStackDescriptorSerializedData using its canonical wire layout.
func (x *NetworkItemStackDescriptorSerializedData) Marshal(io IO) {
	io.Int16(&x.ID)
	io.Uint16(&x.StackSize)
	io.Varuint32(&x.AuxValue)
	Maximum(io, &x.AuxValue, 32767)
	OptionalFunc(io, &x.NetIDVariant, io.Varint32)
	io.Varuint32(&x.BlockRuntimeID)
	io.ByteSlice(&x.UserDataBuffer)
}

type NetworkPermissions struct {
	ServerAuthSoundEnabled bool
}

// Marshal reads or writes NetworkPermissions using its canonical wire layout.
func (x *NetworkPermissions) Marshal(io IO) {
	io.Bool(&x.ServerAuthSoundEnabled)
}

type NewInteractionModel int32

// Marshal reads or writes NewInteractionModel through its int32 wire encoding.
func (x *NewInteractionModel) Marshal(io IO) { io.Varint32((*int32)(x)) }

type PackedItemUseLegacyInventoryTransaction struct {
	LegacyRequestID    ItemStackLegacyRequestID
	LegacySetItemSlots Optional[[]LegacySetSlot]
	ItemUseTransaction ItemUseInventoryTransaction
}

// Marshal reads or writes PackedItemUseLegacyInventoryTransaction using its canonical wire layout.
func (x *PackedItemUseLegacyInventoryTransaction) Marshal(io IO) {
	x.LegacyRequestID.Marshal(io)
	OptionalFunc(io, &x.LegacySetItemSlots, func(value *[]LegacySetSlot) {
		Slice(io, value)
	})
	x.ItemUseTransaction.Marshal(io)
}

type PacketCompressionAlgorithm uint16

// Marshal reads or writes PacketCompressionAlgorithm through its uint16 wire encoding.
func (x *PacketCompressionAlgorithm) Marshal(io IO) { io.Uint16((*uint16)(x)) }

type PacketType uint32

// Marshal reads or writes PacketType through its uint32 wire encoding.
func (x *PacketType) Marshal(io IO) { io.Uint32((*uint32)(x)) }

type PacketViolationSeverity int32

// Marshal reads or writes PacketViolationSeverity through its int32 wire encoding.
func (x *PacketViolationSeverity) Marshal(io IO) { io.Varint32((*int32)(x)) }

type PacketViolationType int32

const (
	PacketViolationTypeUnknown         PacketViolationType = -1
	PacketViolationTypePacketmalformed PacketViolationType = 0
)

// Marshal reads or writes PacketViolationType through its int32 wire encoding.
func (x *PacketViolationType) Marshal(io IO) { io.Varint32((*int32)(x)) }

type PhotoType uint8

// Marshal reads or writes PhotoType through its uint8 wire encoding.
func (x *PhotoType) Marshal(io IO) { io.Uint8((*uint8)(x)) }

type PlayStatusType int32

// Marshal reads or writes PlayStatusType through its int32 wire encoding.
func (x *PlayStatusType) Marshal(io IO) { io.BEInt32((*int32)(x)) }

type PortalCreated struct {
	DimensionID int32
}

func (*PortalCreated) tagEventData() uint32 { return 2 }

// Marshal reads or writes PortalCreated using its canonical wire layout.
func (x *PortalCreated) Marshal(io IO) {
	io.Varint32(&x.DimensionID)
}

type PotionMixDataEntry struct {
	FromPotionID   int32
	FromItemAux    int32
	ReagentItemID  int32
	ReagentItemAux int32
	ToPotionID     int32
	ToItemAux      int32
}

// Marshal reads or writes PotionMixDataEntry using its canonical wire layout.
func (x *PotionMixDataEntry) Marshal(io IO) {
	io.Varint32(&x.FromPotionID)
	io.Varint32(&x.FromItemAux)
	io.Varint32(&x.ReagentItemID)
	io.Varint32(&x.ReagentItemAux)
	io.Varint32(&x.ToPotionID)
	io.Varint32(&x.ToItemAux)
}

type PropertySyncData struct {
	IntEntriesList   []PropertySyncDataPropertySyncIntEntry
	FloatEntriesList []PropertySyncDataPropertySyncFloatEntry
}

// Marshal reads or writes PropertySyncData using its canonical wire layout.
func (x *PropertySyncData) Marshal(io IO) {
	Slice(io, &x.IntEntriesList)
	Slice(io, &x.FloatEntriesList)
}

type PropertySyncDataPropertySyncFloatEntry struct {
	PropertyIndex uint32
	Data          float32
}

// Marshal reads or writes PropertySyncDataPropertySyncFloatEntry using its canonical wire layout.
func (x *PropertySyncDataPropertySyncFloatEntry) Marshal(io IO) {
	io.Varuint32(&x.PropertyIndex)
	io.Float32(&x.Data)
}

type PropertySyncDataPropertySyncIntEntry struct {
	PropertyIndex uint32
	Data          int32
}

// Marshal reads or writes PropertySyncDataPropertySyncIntEntry using its canonical wire layout.
func (x *PropertySyncDataPropertySyncIntEntry) Marshal(io IO) {
	io.Varuint32(&x.PropertyIndex)
	io.Varint32(&x.Data)
}

type RemoveEntry struct {
	Action PlayerListPacketType
	UUID   uuid.UUID
}

func (*RemoveEntry) tagPlayerListData() uint32 { return 0 }

// Marshal reads or writes RemoveEntry using its canonical wire layout.
func (x *RemoveEntry) Marshal(io IO) {
	x.Action.Marshal(io)
	io.UUID(&x.UUID)
}

type RemoveEnvironmentAttributes struct {
	AttributeLayerName      string
	AttributeLayerDimension DimensionType
	Attributes              []string
}

func (*RemoveEnvironmentAttributes) tagAttributeLayerSyncData() uint32 { return 3 }

// Marshal reads or writes RemoveEnvironmentAttributes using its canonical wire layout.
func (x *RemoveEnvironmentAttributes) Marshal(io IO) {
	io.StringLimits(&x.AttributeLayerName, 0, 128)
	x.AttributeLayerDimension.Marshal(io)
	FuncSliceLimits(io, &x.Attributes, io.Varuint32, 0, 1024, func(value *string) {
		io.StringLimits(value, 0, 128)
	})
}

type RemoveOverride struct {
	Type string
}

func (*RemoveOverride) tagPlayerUpdateEntityOverridesData() uint32 { return 1 }

// Marshal reads or writes RemoveOverride using its canonical wire layout.
func (x *RemoveOverride) Marshal(io IO) {
	io.String(&x.Type)
}

type RemoveScore struct {
	Action        string
	ScoreboardID  ScoreboardID
	ObjectiveName Optional[string]
}

func (*RemoveScore) tagSetScoreInfoItem() uint32 { return 0 }

// Marshal reads or writes RemoveScore using its canonical wire layout.
func (x *RemoveScore) Marshal(io IO) {
	io.String(&x.Action)
	x.ScoreboardID.Marshal(io)
	OptionalFunc(io, &x.ObjectiveName, io.String)
}

type RemoveTimeMarkerData struct {
	ClockID       uint64
	TimeMarkerIds []uint64
}

func (*RemoveTimeMarkerData) tagSyncWorldClocksData() uint32 { return 3 }

// Marshal reads or writes RemoveTimeMarkerData using its canonical wire layout.
func (x *RemoveTimeMarkerData) Marshal(io IO) {
	io.Varuint64(&x.ClockID)
	FuncSliceLimits(io, &x.TimeMarkerIds, io.Varuint32, 0, 256, io.Varuint64)
}

type RequestAbilityType uint8

// Marshal reads or writes RequestAbilityType through its uint8 wire encoding.
func (x *RequestAbilityType) Marshal(io IO) { io.Uint8((*uint8)(x)) }

type RequestType uint8

// Marshal reads or writes RequestType through its uint8 wire encoding.
func (x *RequestType) Marshal(io IO) { io.Uint8((*uint8)(x)) }

type RewindType uint8

// Marshal reads or writes RewindType through its uint8 wire encoding.
func (x *RewindType) Marshal(io IO) { io.Uint8((*uint8)(x)) }

type SemVersion struct {
	Version string
}

// Marshal reads or writes SemVersion using its canonical wire layout.
func (x *SemVersion) Marshal(io IO) {
	io.String(&x.Version)
}

type SemVersionData struct {
	Version string
}

// Marshal reads or writes SemVersionData using its canonical wire layout.
func (x *SemVersionData) Marshal(io IO) {
	io.String(&x.Version)
}

type SerializedAbilitiesDataSerializedLayer struct {
	SerializedLayer  uint16
	AbilitiesSet     uint32
	AbilityValues    uint32
	FlySpeed         float32
	VerticalFlySpeed float32
	WalkSpeed        float32
}

// Marshal reads or writes SerializedAbilitiesDataSerializedLayer using its canonical wire layout.
func (x *SerializedAbilitiesDataSerializedLayer) Marshal(io IO) {
	io.Uint16(&x.SerializedLayer)
	io.Uint32(&x.AbilitiesSet)
	io.Uint32(&x.AbilityValues)
	io.Float32(&x.FlySpeed)
	io.Float32(&x.VerticalFlySpeed)
	io.Float32(&x.WalkSpeed)
}

type SerializedSkinRef struct {
	ID                           string
	PlayFabID                    string
	ResourcePatch                string
	ImageData                    SkinImage
	AnimatedImageData            []AnimatedImageData
	CapeImageData                SkinImage
	GeometryData                 string
	GeometryDataMinEngineVersion string
	AnimationData                string
	CapeID                       string
	FullID                       string
	ArmSize                      PersonaArmSizeType
	SkinColour                   color.RGBA
	PersonaPieces                []PersonaPiece
	PieceTintColours             []OrderedEntry[string, TintMapColor]
	IsPremium                    bool
	IsPersona                    bool
	IsPersonaCapeOnClassicSkin   bool
	IsPrimaryUser                bool
	OverridesPlayerAppearance    bool
	TrustedSkinFlag              string
	ProfileHash                  string
}

// Marshal reads or writes SerializedSkinRef using its canonical wire layout.
func (x *SerializedSkinRef) Marshal(io IO) {
	io.String(&x.ID)
	io.String(&x.PlayFabID)
	io.String(&x.ResourcePatch)
	x.ImageData.Marshal(io)
	Slice(io, &x.AnimatedImageData)
	x.CapeImageData.Marshal(io)
	io.String(&x.GeometryData)
	io.String(&x.GeometryDataMinEngineVersion)
	io.String(&x.AnimationData)
	io.String(&x.CapeID)
	io.String(&x.FullID)
	x.ArmSize.Marshal(io)
	io.RGBA(&x.SkinColour)
	Slice(io, &x.PersonaPieces)
	OrderedMap(io, &x.PieceTintColours, io.Varuint32, io.String, func(value *TintMapColor) {
		value.Marshal(io)
	})
	io.Bool(&x.IsPremium)
	io.Bool(&x.IsPersona)
	io.Bool(&x.IsPersonaCapeOnClassicSkin)
	io.Bool(&x.IsPrimaryUser)
	io.Bool(&x.OverridesPlayerAppearance)
	io.String(&x.TrustedSkinFlag)
	io.String(&x.ProfileHash)
}

type ServerBlockProperty struct {
	BlockName       string
	BlockDefinition []byte
}

// Marshal reads or writes ServerBlockProperty using its canonical wire layout.
func (x *ServerBlockProperty) Marshal(io IO) {
	io.String(&x.BlockName)
	io.NBT(&x.BlockDefinition, NBTNetwork)
}

type ServerConfigurationPresenceConfiguration struct {
	RichPresenceID Optional[string]
}

// Marshal reads or writes ServerConfigurationPresenceConfiguration using its canonical wire layout.
func (x *ServerConfigurationPresenceConfiguration) Marshal(io IO) {
	OptionalFunc(io, &x.RichPresenceID, func(value *string) {
		io.StringLimits(value, 0, 50)
	})
}

type ServerConfigurationServerConfigurationJoinInfo struct {
	Gathering             Optional[GatheringJoinInfo]
	ClientStoreEntryPoint Optional[StoreEntryPointInfo]
	Presence              Optional[ServerConfigurationPresenceConfiguration]
}

// Marshal reads or writes ServerConfigurationServerConfigurationJoinInfo using its canonical wire layout.
func (x *ServerConfigurationServerConfigurationJoinInfo) Marshal(io IO) {
	OptionalMarshaler(io, &x.Gathering)
	OptionalMarshaler(io, &x.ClientStoreEntryPoint)
	OptionalMarshaler(io, &x.Presence)
}

type ServerEditorConnectionPolicy int32

const (
	ServerEditorConnectionPolicyMatchworldtype ServerEditorConnectionPolicy = 0
	ServerEditorConnectionPolicyEditoronly     ServerEditorConnectionPolicy = 1
	ServerEditorConnectionPolicyVanillaonly    ServerEditorConnectionPolicy = 2
	ServerEditorConnectionPolicyMixed          ServerEditorConnectionPolicy = 3
)

// Marshal reads or writes ServerEditorConnectionPolicy through its int32 wire encoding.
func (x *ServerEditorConnectionPolicy) Marshal(io IO) { io.Varint32((*int32)(x)) }

type ServerSoundHandle struct {
	ServerSoundHandle uint64
}

// Marshal reads or writes ServerSoundHandle using its canonical wire layout.
func (x *ServerSoundHandle) Marshal(io IO) {
	io.Uint64(&x.ServerSoundHandle)
}

type ServerboundLoadingScreenType int32

// Marshal reads or writes ServerboundLoadingScreenType through its int32 wire encoding.
func (x *ServerboundLoadingScreenType) Marshal(io IO) { io.Varint32((*int32)(x)) }

type ShowStoreOfferRedirectType uint8

// Marshal reads or writes ShowStoreOfferRedirectType through its uint8 wire encoding.
func (x *ShowStoreOfferRedirectType) Marshal(io IO) { io.Uint8((*uint8)(x)) }

type SimulationTypeEnum uint8

// Marshal reads or writes SimulationTypeEnum through its uint8 wire encoding.
func (x *SimulationTypeEnum) Marshal(io IO) { io.Uint8((*uint8)(x)) }

type SlashCommand struct {
	SuccessCount int32
	ErrorCount   int32
	CommandName  string
	ErrorList    string
}

func (*SlashCommand) tagEventData() uint32 { return 8 }

// Marshal reads or writes SlashCommand using its canonical wire layout.
func (x *SlashCommand) Marshal(io IO) {
	io.Varint32(&x.SuccessCount)
	io.Varint32(&x.ErrorCount)
	io.StringLimits(&x.CommandName, 0, 512)
	io.StringLimits(&x.ErrorList, 0, 2048)
}

type SocialEventsServerTelemetryData struct {
	ServerID   string
	ScenarioID string
	WorldID    string
	OwnerID    string
}

// Marshal reads or writes SocialEventsServerTelemetryData using its canonical wire layout.
func (x *SocialEventsServerTelemetryData) Marshal(io IO) {
	io.String(&x.ServerID)
	io.String(&x.ScenarioID)
	io.String(&x.WorldID)
	io.String(&x.OwnerID)
}

type SocialGamePublishSetting int32

// Marshal reads or writes SocialGamePublishSetting through its int32 wire encoding.
func (x *SocialGamePublishSetting) Marshal(io IO) { io.Varint32((*int32)(x)) }

type SoftEnumUpdateType uint8

// Marshal reads or writes SoftEnumUpdateType through its uint8 wire encoding.
func (x *SoftEnumUpdateType) Marshal(io IO) { io.Uint8((*uint8)(x)) }

type SpawnBiomeType int16

// Marshal reads or writes SpawnBiomeType through its int16 wire encoding.
func (x *SpawnBiomeType) Marshal(io IO) { io.Int16((*int16)(x)) }

type SpawnPositionType int32

const (
	SpawnPositionTypePlayerrespawn SpawnPositionType = 0
	SpawnPositionTypeWorldspawn    SpawnPositionType = 1
)

// Marshal reads or writes SpawnPositionType through its int32 wire encoding.
func (x *SpawnPositionType) Marshal(io IO) { io.Varint32((*int32)(x)) }

type SpawnSettings struct {
	SpawnBiomeType       SpawnBiomeType
	UserDefinedBiomeName string
	Dimension            int32
}

// Marshal reads or writes SpawnSettings using its canonical wire layout.
func (x *SpawnSettings) Marshal(io IO) {
	x.SpawnBiomeType.Marshal(io)
	io.String(&x.UserDefinedBiomeName)
	io.Varint32(&x.Dimension)
}

type SphereData struct {
	NumSegments uint8
}

func (*SphereData) tagShape() uint32 { return 5 }

// Marshal reads or writes SphereData using its canonical wire layout.
func (x *SphereData) Marshal(io IO) {
	io.Uint8(&x.NumSegments)
}

type StartVideoCapture struct {
	FrameRate  uint32
	FilePrefix string
}

func (*StartVideoCapture) tagPlayerVideoCaptureData() uint32 { return 0 }

// Marshal reads or writes StartVideoCapture using its canonical wire layout.
func (x *StartVideoCapture) Marshal(io IO) {
	io.Uint32(&x.FrameRate)
	io.String(&x.FilePrefix)
}

type StopVideoCapture struct {
}

func (*StopVideoCapture) tagPlayerVideoCaptureData() uint32 { return 1 }

// Marshal reads or writes StopVideoCapture using its canonical wire layout.
func (x *StopVideoCapture) Marshal(io IO) {
}

type Subtype uint16

// Marshal reads or writes Subtype through its uint16 wire encoding.
func (x *Subtype) Marshal(io IO) { io.Uint16((*uint16)(x)) }

type SyncStateData struct {
	ClockData []SyncWorldClockStateData
}

func (*SyncStateData) tagSyncWorldClocksData() uint32 { return 0 }

// Marshal reads or writes SyncStateData using its canonical wire layout.
func (x *SyncStateData) Marshal(io IO) {
	SliceLimits(io, &x.ClockData, 0, 256)
}

type SyncedAttribute struct {
	AttributeName string
	MinValue      float32
	CurrentValue  float32
	MaxValue      float32
}

// Marshal reads or writes SyncedAttribute using its canonical wire layout.
func (x *SyncedAttribute) Marshal(io IO) {
	io.String(&x.AttributeName)
	io.Float32(&x.MinValue)
	io.Float32(&x.CurrentValue)
	io.Float32(&x.MaxValue)
}

type SynchedActorDataCopyableDataList struct {
	Data []DataItemEntry
}

// Marshal reads or writes SynchedActorDataCopyableDataList using its canonical wire layout.
func (x *SynchedActorDataCopyableDataList) Marshal(io IO) {
	Slice(io, &x.Data)
}

type TargetMode uint8

const (
	TargetModeAngle    TargetMode = 0
	TargetModeDistance TargetMode = 1
)

// Marshal reads or writes TargetMode through its uint8 wire encoding.
func (x *TargetMode) Marshal(io IO) { io.Uint8((*uint8)(x)) }

type TintMapColor struct {
	Colours [4]color.RGBA
}

// Marshal reads or writes TintMapColor using its canonical wire layout.
func (x *TintMapColor) Marshal(io IO) {
	for index1 := range x.Colours {
		io.RGBA(&x.Colours[index1])
	}
}

type TitleType int32

// Marshal reads or writes TitleType through its int32 wire encoding.
func (x *TitleType) Marshal(io IO) { io.Varint32((*int32)(x)) }

type UpdateSubChunkBlocksChangedInfo struct {
	BlocksChangedStandards []UpdateSubChunkNetworkBlockInfo
	BlocksChangedExtras    []UpdateSubChunkNetworkBlockInfo
}

// Marshal reads or writes UpdateSubChunkBlocksChangedInfo using its canonical wire layout.
func (x *UpdateSubChunkBlocksChangedInfo) Marshal(io IO) {
	Slice(io, &x.BlocksChangedStandards)
	Slice(io, &x.BlocksChangedExtras)
}

type UpdateSubChunkNetworkBlockInfo struct {
	Pos                       BlockPos
	RuntimeID                 uint32
	UpdateFlags               uint32
	SyncMessageEntityUniqueID uint64
	SyncMessageMessage        uint32
}

// Marshal reads or writes UpdateSubChunkNetworkBlockInfo using its canonical wire layout.
func (x *UpdateSubChunkNetworkBlockInfo) Marshal(io IO) {
	x.Pos.Marshal(io)
	io.Varuint32(&x.RuntimeID)
	io.Varuint32(&x.UpdateFlags)
	io.ActorUniqueIDVaruint64(&x.SyncMessageEntityUniqueID)
	io.Varuint32(&x.SyncMessageMessage)
}

type VillageType uint8

const (
	VillageTypeDesert  VillageType = 0
	VillageTypeIce     VillageType = 1
	VillageTypeSavanna VillageType = 2
	VillageTypeTaiga   VillageType = 3
	VillageTypeDefault VillageType = 4
)

// Marshal reads or writes VillageType through its uint8 wire encoding.
func (x *VillageType) Marshal(io IO) { io.Uint8((*uint8)(x)) }
