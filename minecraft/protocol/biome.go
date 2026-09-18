package protocol

// BiomeCappedSurface specifies the materials to use for the capped surface of a biome, such as in the Nether.
type BiomeCappedSurface struct {
	// FloorBlocks is a list of runtime IDs to use for the floor blocks.
	FloorBlocks []uint32
	// CeilingBlocks is a list of runtime IDs to use for the ceiling blocks.
	CeilingBlocks []uint32
	// SeaBlock is an optional runtime ID to use for the sea block.
	SeaBlock Optional[uint32]
	// FoundationBlock is an optional runtime ID to use for the foundation block.
	FoundationBlock Optional[uint32]
	// BeachBlock is an optional runtime ID to use for the beach block.
	BeachBlock Optional[uint32]
}

// Marshal reads or writes BiomeCappedSurface using its canonical wire layout.
func (x *BiomeCappedSurface) Marshal(io IO) {
	FuncSlice(io, &x.FloorBlocks, io.Varuint32, io.Uint32)
	FuncSlice(io, &x.CeilingBlocks, io.Varuint32, io.Uint32)
	OptionalFunc(io, &x.SeaBlock, io.Uint32)
	OptionalFunc(io, &x.FoundationBlock, io.Uint32)
	OptionalFunc(io, &x.BeachBlock, io.Uint32)
}

// BiomeClimate represents the climate of a biome, mainly for ambience but also defines certain behaviours.
type BiomeClimate struct {
	// Temperature is the temperature of the biome, used for weather, biome behaviours and sky colour.
	Temperature float32
	// Downfall is the amount that precipitation affects colours and block changes.
	Downfall float32
	// SnowAccumulationMin is the minimum amount of snow that can accumulate in the biome, every 0.125 is another
	// layer of snow.
	SnowAccumulationMin float32
	// SnowAccumulationMax is the maximum amount of snow that can accumulate in the biome, every 0.125 is another
	// layer of snow.
	SnowAccumulationMax float32
}

// Marshal reads or writes BiomeClimate using its canonical wire layout.
func (x *BiomeClimate) Marshal(io IO) {
	io.Float32(&x.Temperature)
	io.Float32(&x.Downfall)
	io.Float32(&x.SnowAccumulationMin)
	io.Float32(&x.SnowAccumulationMax)
}

// BiomeConditionalTransformation is the legacy method of transforming biomes.
type BiomeConditionalTransformation struct {
	// WeightedBiomes is a list of biomes and their weights.
	WeightedBiomes []BiomeWeightedData
	// ConditionJSON is an index of the condition JSON data in the string list.
	ConditionJSON uint16
	// MinPassingNeighbours is the minimum number of neighbours that must pass the condition for the
	// transformation to be applied.
	MinPassingNeighbours uint32
}

// Marshal reads or writes BiomeConditionalTransformation using its canonical wire layout.
func (x *BiomeConditionalTransformation) Marshal(io IO) {
	Slice(io, &x.WeightedBiomes)
	io.Uint16(&x.ConditionJSON)
	io.Uint32(&x.MinPassingNeighbours)
}

// BiomeConsolidatedFeature represents a feature that is consolidated into a single feature for the biome.
type BiomeConsolidatedFeature struct {
	// Scatter defines how the feature is scattered in the biome.
	Scatter BiomeScatterParameter
	// Feature is the index of the feature's name in the string list.
	Feature uint16
	// Identifier is the index of the feature's identifier in the string list.
	Identifier uint16
	// Pass is the index of the feature's pass in the string list.
	Pass uint16
	// CanUseInternal is true if the feature can use internal features.
	CanUseInternal bool
}

// Marshal reads or writes BiomeConsolidatedFeature using its canonical wire layout.
func (x *BiomeConsolidatedFeature) Marshal(io IO) {
	x.Scatter.Marshal(io)
	io.Uint16(&x.Feature)
	io.Uint16(&x.Identifier)
	io.Uint16(&x.Pass)
	io.Bool(&x.CanUseInternal)
}

type BiomeConsolidatedFeaturesData struct {
	Features []BiomeConsolidatedFeature
}

// Marshal reads or writes BiomeConsolidatedFeaturesData using its canonical wire layout.
func (x *BiomeConsolidatedFeaturesData) Marshal(io IO) {
	Slice(io, &x.Features)
}

// BiomeCoordinate specifies coordinate rules for where features can be scattered in the biome.
type BiomeCoordinate struct {
	// MinValueType is the type of expression operation to use for the minimum value, and is one of the
	// BiomeExpressionOp constants above.
	MinValueType int32
	// MinValue is the index of the minimum value expression in the string list.
	MinValue uint16
	// MaxValueType is the type of expression operation to use for the maximum value, and is one of the
	MaxValueType int32
	// MaxValue is the index of the maximum value expression in the string list.
	MaxValue uint16
	// GridOffset is the offset of the grid, used for fixed grid and jittered grid distributions.
	GridOffset uint32
	// GridStepSize is the step size of the grid, used for fixed grid and jittered grid distributions.
	GridStepSize uint32
	// Distribution is the type of distribution to use for the coordinate, and is one of the
	// BiomeRandomDistributionType constants above.
	Distribution RandomDistributionType
}

// Marshal reads or writes BiomeCoordinate using its canonical wire layout.
func (x *BiomeCoordinate) Marshal(io IO) {
	io.Varint32(&x.MinValueType)
	io.Uint16(&x.MinValue)
	io.Varint32(&x.MaxValueType)
	io.Uint16(&x.MaxValue)
	io.Uint32(&x.GridOffset)
	io.Uint32(&x.GridStepSize)
	x.Distribution.Marshal(io)
}

// BiomeDefinition represents a biome definition in the game. This can be a vanilla biome or a completely
// custom biome.
type BiomeDefinition struct {
	// NameIndex represents the index of the biome name in the string list.
	NameIndex uint16
	// Temperature is the temperature of the biome, used for weather, biome behaviours and sky colour.
	Temperature float32
	// Downfall is the amount that precipitation affects colours and block changes.
	Downfall float32
	// FoliageSnow is the progression factor for foliage turning white due to snow.
	FoliageSnow float32
	// Depth is the depth of the biome.
	Depth float32
	// Scale is the scale of the biome.
	Scale float32
	// BiomeID is the biome ID.
	BiomeID int32
	// Rain is true if the biome has rain, false if it is a dry biome.
	Rain bool
	// Tags are a list of indices of tags in the string list. These are used to group biomes together for biome
	// generation and other purposes.
	Tags Optional[BiomeTagsData]
	// ChunkGeneration is optional information to assist in client-side chunk generation. Almost all servers can
	// and should leave this empty to greatly reduce the size of this packet. Only BDS and servers which *exactly*
	// match the vanilla chunk generation can benefit from this.
	ChunkGeneration Optional[BiomeDefinitionChunkGenData]
}

// Marshal reads or writes BiomeDefinition using its canonical wire layout.
func (x *BiomeDefinition) Marshal(io IO) {
	io.Uint16(&x.NameIndex)
	io.Float32(&x.Temperature)
	io.Float32(&x.Downfall)
	io.Float32(&x.FoliageSnow)
	io.Float32(&x.Depth)
	io.Float32(&x.Scale)
	io.Int32(&x.BiomeID)
	io.Bool(&x.Rain)
	OptionalMarshaler(io, &x.Tags)
	OptionalMarshaler(io, &x.ChunkGeneration)
}

type BiomeDefinitionChunkGenData struct {
	Climate                    Optional[BiomeClimate]
	ConsolidatedFeatures       Optional[BiomeConsolidatedFeaturesData]
	MountainParams             Optional[BiomeMountainParameters]
	SurfaceMaterialAdjustments Optional[BiomeSurfaceMaterialAdjustmentData]
	OverworldGenRules          Optional[BiomeOverworldGenRulesData]
	MultinoiseGenRules         Optional[BiomeMultiNoiseRules]
	LegacyWorldGenRules        Optional[BiomeLegacyWorldGenRulesData]
	ReplacementBiomes          Optional[BiomeReplacementsData]
	VillageType                Optional[VillageType]
	SurfaceBuilderData         Optional[BiomeSurfaceBuilder]
	SubsurfaceBuilderData      Optional[BiomeSurfaceBuilder]
}

// Marshal reads or writes BiomeDefinitionChunkGenData using its canonical wire layout.
func (x *BiomeDefinitionChunkGenData) Marshal(io IO) {
	OptionalMarshaler(io, &x.Climate)
	OptionalMarshaler(io, &x.ConsolidatedFeatures)
	OptionalMarshaler(io, &x.MountainParams)
	OptionalMarshaler(io, &x.SurfaceMaterialAdjustments)
	OptionalMarshaler(io, &x.OverworldGenRules)
	OptionalMarshaler(io, &x.MultinoiseGenRules)
	OptionalMarshaler(io, &x.LegacyWorldGenRules)
	OptionalMarshaler(io, &x.ReplacementBiomes)
	OptionalMarshaler(io, &x.VillageType)
	OptionalMarshaler(io, &x.SurfaceBuilderData)
	OptionalMarshaler(io, &x.SubsurfaceBuilderData)
}

// BiomeElementData are set rules to adjust the surface materials of the biome.
type BiomeElementData struct {
	// NoiseFrequencyScale is the frequency scale of the noise used to adjust the surface materials.
	NoiseFrequencyScale float32
	// NoiseLowerBound is the minimum noise value required to be selected.
	NoiseLowerBound float32
	// NoiseUpperBound is the maximum noise value required to be selected.
	NoiseUpperBound float32
	// HeightMinType is the type of expression operation to use for the minimum height, and is one of the
	// BiomeExpressionOp constants above.
	HeightMinType int32
	// HeightMin is the index of the minimum height expression in the string list.
	HeightMin uint16
	// HeightMaxType is the type of expression operation to use for the maximum height, and is one of the
	// BiomeExpressionOp constants above.
	HeightMaxType int32
	// HeightMax is the index of the maximum height expression in the string list.
	HeightMax uint16
	// AdjustedMaterials is the materials to use for the surface layers of the biome if selected.
	AdjustedMaterials BiomeSurfaceMaterial
}

// Marshal reads or writes BiomeElementData using its canonical wire layout.
func (x *BiomeElementData) Marshal(io IO) {
	io.Float32(&x.NoiseFrequencyScale)
	io.Float32(&x.NoiseLowerBound)
	io.Float32(&x.NoiseUpperBound)
	io.Varint32(&x.HeightMinType)
	io.Uint16(&x.HeightMin)
	io.Varint32(&x.HeightMaxType)
	io.Uint16(&x.HeightMax)
	x.AdjustedMaterials.Marshal(io)
}

type BiomeLegacyWorldGenRulesData struct {
	LegacyPreHillsEdge []BiomeConditionalTransformation
}

// Marshal reads or writes BiomeLegacyWorldGenRulesData using its canonical wire layout.
func (x *BiomeLegacyWorldGenRulesData) Marshal(io IO) {
	Slice(io, &x.LegacyPreHillsEdge)
}

// BiomeMesaSurface specifies the materials to use for the mesa biome.
type BiomeMesaSurface struct {
	// ClayMaterial is the runtime ID of the block to use for clay layers.
	ClayMaterial uint32
	// HardClayMaterial is the runtime ID of the block to use for hard clay layers.
	HardClayMaterial uint32
	// BrycePillars is true if the biome has bryce pillars, which are tall spire-like structures.
	BrycePillars bool
	// HasForest is true if the biome has a forest.
	HasForest bool
}

// Marshal reads or writes BiomeMesaSurface using its canonical wire layout.
func (x *BiomeMesaSurface) Marshal(io IO) {
	io.Uint32(&x.ClayMaterial)
	io.Uint32(&x.HardClayMaterial)
	io.Bool(&x.BrycePillars)
	io.Bool(&x.HasForest)
}

// BiomeMountainParameters specifies the parameters for a mountain biome.
type BiomeMountainParameters struct {
	// SteepBlock is the runtime ID of the block to use for steep slopes.
	SteepBlock uint32
	// NorthSlopes is true if the biome has north slopes.
	NorthSlopes bool
	// SouthSlopes is true if the biome has south slopes.
	SouthSlopes bool
	// WestSlopes is true if the biome has west slopes.
	WestSlopes bool
	// EastSlopes is true if the biome has east slopes.
	EastSlopes bool
	// TopSlideEnabled is true if the biome has top slide enabled.
	TopSlideEnabled bool
}

// Marshal reads or writes BiomeMountainParameters using its canonical wire layout.
func (x *BiomeMountainParameters) Marshal(io IO) {
	io.Uint32(&x.SteepBlock)
	io.Bool(&x.NorthSlopes)
	io.Bool(&x.SouthSlopes)
	io.Bool(&x.WestSlopes)
	io.Bool(&x.EastSlopes)
	io.Bool(&x.TopSlideEnabled)
}

// BiomeMultiNoiseRules specifies the rules for multi-noise biomes, which are biomes that are defined by
// multiple noise parameters instead of just temperature and humidity.
type BiomeMultiNoiseRules struct {
	// Temperature is the temperature level of the biome.
	Temperature float32
	// Humidity is the humidity level of the biome.
	Humidity float32
	// Altitude is the altitude level of the biome.
	Altitude float32
	// Weirdness is the weirdness level of the biome.
	Weirdness float32
	// Weight is the weight of the biome, with a higher weight being more likely to be selected.
	Weight float32
}

// Marshal reads or writes BiomeMultiNoiseRules using its canonical wire layout.
func (x *BiomeMultiNoiseRules) Marshal(io IO) {
	io.Float32(&x.Temperature)
	io.Float32(&x.Humidity)
	io.Float32(&x.Altitude)
	io.Float32(&x.Weirdness)
	io.Float32(&x.Weight)
}

// BiomeNoiseGradientSurface specifies noise-gradient surface block data for a biome.
type BiomeNoiseGradientSurface struct {
	// NonReplaceableBlocks is a list of block runtime IDs that may not be replaced.
	NonReplaceableBlocks []uint32
	// GradientBlocks is a list of noise block specifiers used by the gradient.
	GradientBlocks []NoiseBlockSpecifier
	// Noise is the noise descriptor used by the gradient.
	Noise NoiseDescriptor
}

// Marshal reads or writes BiomeNoiseGradientSurface using its canonical wire layout.
func (x *BiomeNoiseGradientSurface) Marshal(io IO) {
	FuncSlice(io, &x.NonReplaceableBlocks, io.Varuint32, io.Uint32)
	Slice(io, &x.GradientBlocks)
	x.Noise.Marshal(io)
}

type BiomeOverworldGenRulesData struct {
	HillsTransformations  []BiomeWeightedData
	MutateTransformations []BiomeWeightedData
	RiverTransformations  []BiomeWeightedData
	ShoreTransformations  []BiomeWeightedData
	PreHillsEdge          []BiomeConditionalTransformation
	PostShoreEdge         []BiomeConditionalTransformation
	Climate               []BiomeTemperatureWeight
}

// Marshal reads or writes BiomeOverworldGenRulesData using its canonical wire layout.
func (x *BiomeOverworldGenRulesData) Marshal(io IO) {
	Slice(io, &x.HillsTransformations)
	Slice(io, &x.MutateTransformations)
	Slice(io, &x.RiverTransformations)
	Slice(io, &x.ShoreTransformations)
	Slice(io, &x.PreHillsEdge)
	Slice(io, &x.PostShoreEdge)
	Slice(io, &x.Climate)
}

// BiomeReplacementData represents data for biome replacements.
type BiomeReplacementData struct {
	// Biome is the biome ID to replace.
	Biome uint16
	// Dimension is the dimension ID where the replacement applies.
	Dimension uint16
	// TargetBiomes is a list of target biome IDs for the replacement.
	TargetBiomes []uint16
	// Amount is the amount of replacement to apply.
	Amount float32
	// NoiseFrequencyScale ...
	NoiseFrequencyScale float32
	// ReplacementIndex is the index of the replacement.
	ReplacementIndex uint32
}

// Marshal reads or writes BiomeReplacementData using its canonical wire layout.
func (x *BiomeReplacementData) Marshal(io IO) {
	io.Uint16(&x.Biome)
	io.Uint16(&x.Dimension)
	FuncSlice(io, &x.TargetBiomes, io.Varuint32, io.Uint16)
	io.Float32(&x.Amount)
	io.Float32(&x.NoiseFrequencyScale)
	io.Uint32(&x.ReplacementIndex)
}

type BiomeReplacementsData struct {
	BiomeReplacements []BiomeReplacementData
}

// Marshal reads or writes BiomeReplacementsData using its canonical wire layout.
func (x *BiomeReplacementsData) Marshal(io IO) {
	Slice(io, &x.BiomeReplacements)
}

type BiomeScatterParameter struct {
	// Coordinates is a list of coordinate rules to scatter the feature within.
	Coordinates []BiomeCoordinate
	// EvaluationOrder is the order in which the coordinates are evaluated, and is one of the
	// CoordinateEvaluationOrder constants above.
	EvaluationOrder CoordinateEvaluationOrder
	// ChancePercentType is the type of expression operation to use for the chance percent, and is one of the
	// BiomeExpressionOp constants above.
	ChancePercentType int32
	// ChangePercent is the index of the chance expression in the string list.
	ChancePercent uint16
	// ChanceNumerator is the numerator of the chance expression.
	ChanceNumerator int32
	// ChanceDenominator is the denominator of the chance expression.
	ChanceDenominator int32
	// IterationsType is the type of expression operation to use for the iterations, and is one of the
	// BiomeExpressionOp constants above.
	IterationsType int32
	// Iterations is the index of the iterations expression in the string list.
	Iterations uint16
}

// Marshal reads or writes BiomeScatterParameter using its canonical wire layout.
func (x *BiomeScatterParameter) Marshal(io IO) {
	Slice(io, &x.Coordinates)
	x.EvaluationOrder.Marshal(io)
	io.Varint32(&x.ChancePercentType)
	io.Uint16(&x.ChancePercent)
	io.Int32(&x.ChanceNumerator)
	io.Int32(&x.ChanceDenominator)
	io.Varint32(&x.IterationsType)
	io.Uint16(&x.Iterations)
}

type BiomeStringList struct {
	Strings []string
}

// Marshal reads or writes BiomeStringList using its canonical wire layout.
func (x *BiomeStringList) Marshal(io IO) {
	FuncSlice(io, &x.Strings, io.Varuint32, io.String)
}

// BiomeSurfaceBuilder specifies the materials and special surface rules to use for a biome surface.
type BiomeSurfaceBuilder struct {
	// SurfaceMaterials is a set of materials to use for the surface layers of the biome.
	SurfaceMaterials Optional[BiomeSurfaceMaterial]
	// HasDefaultOverworldSurface is true if the biome has a default overworld surface.
	HasDefaultOverworldSurface bool
	// HasSwampSurface is true if the biome has a swamp surface.
	HasSwampSurface bool
	// HasFrozenOceanSurface is true if the biome has a frozen ocean surface.
	HasFrozenOceanSurface bool
	// HasTheEndSurface is true if the biome has an end surface.
	HasEndSurface bool
	// MesaSurface is optional information to specify the biome's mesa surface.
	MesaSurface Optional[BiomeMesaSurface]
	// CappedSurface is optional information to specify the biome's capped surface, i.e. in the Nether.
	CappedSurface Optional[BiomeCappedSurface]
	// NoiseGradientSurface is optional information to specify noise-gradient surface data.
	NoiseGradientSurface Optional[BiomeNoiseGradientSurface]
}

// Marshal reads or writes BiomeSurfaceBuilder using its canonical wire layout.
func (x *BiomeSurfaceBuilder) Marshal(io IO) {
	OptionalMarshaler(io, &x.SurfaceMaterials)
	io.Bool(&x.HasDefaultOverworldSurface)
	io.Bool(&x.HasSwampSurface)
	io.Bool(&x.HasFrozenOceanSurface)
	io.Bool(&x.HasEndSurface)
	OptionalMarshaler(io, &x.MesaSurface)
	OptionalMarshaler(io, &x.CappedSurface)
	OptionalMarshaler(io, &x.NoiseGradientSurface)
}

// BiomeSurfaceMaterial specifies the materials to use for the surface layers of the biome.
type BiomeSurfaceMaterial struct {
	// TopBlock is the runtime ID of the block to use for the top layer.
	TopBlock uint32
	// MidBlock is the runtime ID to use for the middle layers.
	MidBlock uint32
	// SeaFloorBlock is the runtime ID to use for the sea floor.
	SeaFloorBlock uint32
	// FoundationBlock is the runtime ID to use for the foundation layers.
	FoundationBlock uint32
	// SeaBlock is the runtime ID to use for the sea layers.
	SeaBlock uint32
	// SeaFloorDepth is the depth of the sea floor, in blocks.
	SeaFloorDepth int32
}

// Marshal reads or writes BiomeSurfaceMaterial using its canonical wire layout.
func (x *BiomeSurfaceMaterial) Marshal(io IO) {
	io.Uint32(&x.TopBlock)
	io.Uint32(&x.MidBlock)
	io.Uint32(&x.SeaFloorBlock)
	io.Uint32(&x.FoundationBlock)
	io.Uint32(&x.SeaBlock)
	io.Int32(&x.SeaFloorDepth)
}

type BiomeSurfaceMaterialAdjustmentData struct {
	Adjustments []BiomeElementData
}

// Marshal reads or writes BiomeSurfaceMaterialAdjustmentData using its canonical wire layout.
func (x *BiomeSurfaceMaterialAdjustmentData) Marshal(io IO) {
	Slice(io, &x.Adjustments)
}

type BiomeTagsData struct {
	Tags []uint16
}

// Marshal reads or writes BiomeTagsData using its canonical wire layout.
func (x *BiomeTagsData) Marshal(io IO) {
	FuncSlice(io, &x.Tags, io.Varuint32, io.Uint16)
}

// BiomeTemperatureWeight defines the weight for a temperature, used for weighted randomness.
type BiomeTemperatureWeight struct {
	// Temperature is the temperature that can be selected.
	Temperature int32
	// Weight is the weight of the temperature, with a higher weight being more likely to be selected.
	Weight uint32
}

// Marshal reads or writes BiomeTemperatureWeight using its canonical wire layout.
func (x *BiomeTemperatureWeight) Marshal(io IO) {
	io.Varint32(&x.Temperature)
	io.Uint32(&x.Weight)
}

type BiomeWeightedData struct {
	BiomeIdentifier uint16
	Weight          uint32
}

// Marshal reads or writes BiomeWeightedData using its canonical wire layout.
func (x *BiomeWeightedData) Marshal(io IO) {
	io.Uint16(&x.BiomeIdentifier)
	io.Uint32(&x.Weight)
}

// FloatRange is an inclusive minimum/maximum pair of float32 values.
type FloatRange struct {
	// Min is the minimum value of the range.
	Min float32
	// Max is the maximum value of the range.
	Max float32
}

// Marshal reads or writes FloatRange using its canonical wire layout.
func (x *FloatRange) Marshal(io IO) {
	io.Float32(&x.Min)
	io.Float32(&x.Max)
}

type Mirror uint8

const (
	BiomeCoordinateEvaluationOrderXYZ Mirror = 0
	BiomeCoordinateEvaluationOrderXZY Mirror = 1
	BiomeCoordinateEvaluationOrderYXZ Mirror = 2
	BiomeCoordinateEvaluationOrderYZX Mirror = 3
)

// Marshal reads or writes Mirror through its uint8 wire encoding.
func (x *Mirror) Marshal(io IO) { io.Uint8((*uint8)(x)) }

// NoiseBlockSpecifier specifies a block placed by the gradient noise based on a threshold and range.
type NoiseBlockSpecifier struct {
	// Noise is the noise name.
	Noise string
	// Threshold is the noise threshold above which the block is placed.
	Threshold float32
	// Range is the noise range within which the block is placed.
	Range FloatRange
	// Block is the block runtime ID placed by this specifier.
	Block uint32
}

// Marshal reads or writes NoiseBlockSpecifier using its canonical wire layout.
func (x *NoiseBlockSpecifier) Marshal(io IO) {
	io.String(&x.Noise)
	io.Float32(&x.Threshold)
	x.Range.Marshal(io)
	io.Uint32(&x.Block)
}

// NoiseDescriptor describes the gradient noise used by a BiomeNoiseGradientSurface.
type NoiseDescriptor struct {
	// Name is the string used to initialise the noise.
	Name string
	// FirstOctave is the first octave used by the noise.
	FirstOctave int32
	// Amplitudes is a list of amplitude values used by the noise. It must contain between 1 and 100 entries.
	Amplitudes []float32
}

// Marshal reads or writes NoiseDescriptor using its canonical wire layout.
func (x *NoiseDescriptor) Marshal(io IO) {
	io.String(&x.Name)
	io.Int32(&x.FirstOctave)
	FuncSliceLimits(io, &x.Amplitudes, io.Varuint32, 1, 100, io.Float32)
}

type PacketViolationType int32

const (
	BiomeExpressionOpUnknown   PacketViolationType = -1
	BiomeExpressionOpLeftBrace PacketViolationType = 0
)

// Marshal reads or writes PacketViolationType through its int32 wire encoding.
func (x *PacketViolationType) Marshal(io IO) { io.Varint32((*int32)(x)) }

type RandomDistributionType int32

const (
	BiomeRandomDistributionTypeSingleValued    RandomDistributionType = 0
	BiomeRandomDistributionTypeUniform         RandomDistributionType = 1
	BiomeRandomDistributionTypeGaussian        RandomDistributionType = 2
	BiomeRandomDistributionTypeInverseGaussian RandomDistributionType = 3
	BiomeRandomDistributionTypeFixedGrid       RandomDistributionType = 4
	BiomeRandomDistributionTypeJitteredGrid    RandomDistributionType = 5
	BiomeRandomDistributionTypeTriangle        RandomDistributionType = 6
)

// Marshal reads or writes RandomDistributionType through its int32 wire encoding.
func (x *RandomDistributionType) Marshal(io IO) { io.Varint32((*int32)(x)) }
