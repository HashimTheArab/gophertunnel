// Code generated from canonical protocol manifest v2. DO NOT EDIT.

package protocol

type StructureTemplateRequestOperation uint8

const (
	FurnaceLeftTabNone         StructureTemplateRequestOperation = 0
	FurnaceLeftTabRecipeFood   StructureTemplateRequestOperation = 1
	FurnaceLeftTabRecipeItems  StructureTemplateRequestOperation = 2
	FurnaceLeftTabRecipeBlocks StructureTemplateRequestOperation = 3
)

// Marshal reads or writes StructureTemplateRequestOperation through its uint8 wire encoding.
func (x *StructureTemplateRequestOperation) Marshal(io IO) { io.Uint8((*uint8)(x)) }

type StructureTemplateResponseType uint8

const (
	FurnaceLayoutNone          StructureTemplateResponseType = 0
	FurnaceLayoutInventoryOnly StructureTemplateResponseType = 1
	FurnaceLayoutDefault       StructureTemplateResponseType = 2
)

// Marshal reads or writes StructureTemplateResponseType through its uint8 wire encoding.
func (x *StructureTemplateResponseType) Marshal(io IO) { io.Uint8((*uint8)(x)) }
