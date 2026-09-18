package packet

import "github.com/sandertv/gophertunnel/minecraft/protocol"

const (
	PermissionLevelVisitor  protocol.PlayerPermissionLevel = 0
	PermissionLevelMember   protocol.PlayerPermissionLevel = 1
	PermissionLevelOperator protocol.PlayerPermissionLevel = 2
	PermissionLevelCustom   protocol.PlayerPermissionLevel = 3
)
