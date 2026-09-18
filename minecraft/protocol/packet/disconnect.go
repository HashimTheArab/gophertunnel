package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

const (
	DisconnectReasonUnknown                                            protocol.ConnectionDisconnectFailReason = 0
	DisconnectReasonCantConnectNoInternet                              protocol.ConnectionDisconnectFailReason = 1
	DisconnectReasonNoPermissions                                      protocol.ConnectionDisconnectFailReason = 2
	DisconnectReasonUnrecoverableError                                 protocol.ConnectionDisconnectFailReason = 3
	DisconnectReasonThirdPartyBlocked                                  protocol.ConnectionDisconnectFailReason = 4
	DisconnectReasonThirdPartyNoInternet                               protocol.ConnectionDisconnectFailReason = 5
	DisconnectReasonThirdPartyBadIP                                    protocol.ConnectionDisconnectFailReason = 6
	DisconnectReasonThirdPartyNoServerOrServerLocked                   protocol.ConnectionDisconnectFailReason = 7
	DisconnectReasonVersionMismatch                                    protocol.ConnectionDisconnectFailReason = 8
	DisconnectReasonSkinIssue                                          protocol.ConnectionDisconnectFailReason = 9
	DisconnectReasonInviteSessionNotFound                              protocol.ConnectionDisconnectFailReason = 10
	DisconnectReasonEduLevelSettingsMissing                            protocol.ConnectionDisconnectFailReason = 11
	DisconnectReasonLocalServerNotFound                                protocol.ConnectionDisconnectFailReason = 12
	DisconnectReasonLegacyDisconnect                                   protocol.ConnectionDisconnectFailReason = 13
	DisconnectReasonUserLeaveGameAttempted                             protocol.ConnectionDisconnectFailReason = 14
	DisconnectReasonPlatformLockedSkinsError                           protocol.ConnectionDisconnectFailReason = 15
	DisconnectReasonRealmsWorldUnassigned                              protocol.ConnectionDisconnectFailReason = 16
	DisconnectReasonRealmsServerCantConnect                            protocol.ConnectionDisconnectFailReason = 17
	DisconnectReasonRealmsServerHidden                                 protocol.ConnectionDisconnectFailReason = 18
	DisconnectReasonRealmsServerDisabledBeta                           protocol.ConnectionDisconnectFailReason = 19
	DisconnectReasonRealmsServerDisabled                               protocol.ConnectionDisconnectFailReason = 20
	DisconnectReasonCrossPlatformDisabled                              protocol.ConnectionDisconnectFailReason = 21
	DisconnectReasonCantConnect                                        protocol.ConnectionDisconnectFailReason = 22
	DisconnectReasonSessionNotFound                                    protocol.ConnectionDisconnectFailReason = 23
	ConnectionDisconnectFailReasonClientSettingsIncompatibleWithServer protocol.ConnectionDisconnectFailReason = 24
	DisconnectReasonServerFull                                         protocol.ConnectionDisconnectFailReason = 25
	DisconnectReasonInvalidPlatformSkin                                protocol.ConnectionDisconnectFailReason = 26
	DisconnectReasonEditionVersionMismatch                             protocol.ConnectionDisconnectFailReason = 27
	DisconnectReasonEditionMismatch                                    protocol.ConnectionDisconnectFailReason = 28
	DisconnectReasonLevelNewerThanExeVersion                           protocol.ConnectionDisconnectFailReason = 29
	DisconnectReasonNoFailOccurred                                     protocol.ConnectionDisconnectFailReason = 30
	DisconnectReasonBannedSkin                                         protocol.ConnectionDisconnectFailReason = 31
	DisconnectReasonTimeout                                            protocol.ConnectionDisconnectFailReason = 32
	DisconnectReasonServerNotFound                                     protocol.ConnectionDisconnectFailReason = 33
	DisconnectReasonOutdatedServer                                     protocol.ConnectionDisconnectFailReason = 34
	DisconnectReasonOutdatedClient                                     protocol.ConnectionDisconnectFailReason = 35
	ConnectionDisconnectFailReasonNoPremiumPlatform                    protocol.ConnectionDisconnectFailReason = 36
	DisconnectReasonMultiplayerDisabled                                protocol.ConnectionDisconnectFailReason = 37
	DisconnectReasonNoWiFi                                             protocol.ConnectionDisconnectFailReason = 38
	ConnectionDisconnectFailReasonWorldCorruption                      protocol.ConnectionDisconnectFailReason = 39
	DisconnectReasonNoReason                                           protocol.ConnectionDisconnectFailReason = 40
	DisconnectReasonDisconnected                                       protocol.ConnectionDisconnectFailReason = 41
	DisconnectReasonInvalidPlayer                                      protocol.ConnectionDisconnectFailReason = 42
	DisconnectReasonLoggedInOtherLocation                              protocol.ConnectionDisconnectFailReason = 43
	DisconnectReasonServerIdConflict                                   protocol.ConnectionDisconnectFailReason = 44
	DisconnectReasonNotAllowed                                         protocol.ConnectionDisconnectFailReason = 45
	DisconnectReasonNotAuthenticated                                   protocol.ConnectionDisconnectFailReason = 46
	DisconnectReasonInvalidTenant                                      protocol.ConnectionDisconnectFailReason = 47
	DisconnectReasonUnknownPacket                                      protocol.ConnectionDisconnectFailReason = 48
	DisconnectReasonUnexpectedPacket                                   protocol.ConnectionDisconnectFailReason = 49
	DisconnectReasonInvalidCommandRequestPacket                        protocol.ConnectionDisconnectFailReason = 50
	DisconnectReasonHostSuspended                                      protocol.ConnectionDisconnectFailReason = 51
	DisconnectReasonLoginPacketNoRequest                               protocol.ConnectionDisconnectFailReason = 52
	DisconnectReasonLoginPacketNoCert                                  protocol.ConnectionDisconnectFailReason = 53
	DisconnectReasonMissingClient                                      protocol.ConnectionDisconnectFailReason = 54
	DisconnectReasonKicked                                             protocol.ConnectionDisconnectFailReason = 55
	DisconnectReasonKickedForExploit                                   protocol.ConnectionDisconnectFailReason = 56
	DisconnectReasonKickedForIdle                                      protocol.ConnectionDisconnectFailReason = 57
	DisconnectReasonResourcePackProblem                                protocol.ConnectionDisconnectFailReason = 58
	DisconnectReasonIncompatiblePack                                   protocol.ConnectionDisconnectFailReason = 59
	DisconnectReasonOutOfStorage                                       protocol.ConnectionDisconnectFailReason = 60
	DisconnectReasonInvalidLevel                                       protocol.ConnectionDisconnectFailReason = 61
	ConnectionDisconnectFailReasonDisconnectPacket                     protocol.ConnectionDisconnectFailReason = 62
	DisconnectReasonBlockMismatch                                      protocol.ConnectionDisconnectFailReason = 63
	DisconnectReasonInvalidHeights                                     protocol.ConnectionDisconnectFailReason = 64
	DisconnectReasonInvalidWidths                                      protocol.ConnectionDisconnectFailReason = 65
	ConnectionDisconnectFailReasonConnectionLost                       protocol.ConnectionDisconnectFailReason = 66
	ConnectionDisconnectFailReasonZombieConnection                     protocol.ConnectionDisconnectFailReason = 67
	DisconnectReasonShutdown                                           protocol.ConnectionDisconnectFailReason = 68
	ConnectionDisconnectFailReasonReasonNotSet                         protocol.ConnectionDisconnectFailReason = 69
	DisconnectReasonLoadingStateTimeout                                protocol.ConnectionDisconnectFailReason = 70
	DisconnectReasonResourcePackLoadingFailed                          protocol.ConnectionDisconnectFailReason = 71
	DisconnectReasonSearchingForSessionLoadingScreenFailed             protocol.ConnectionDisconnectFailReason = 72
	DisconnectReasonNetherNetProtocolVersion                           protocol.ConnectionDisconnectFailReason = 73
	DisconnectReasonSubsystemStatusError                               protocol.ConnectionDisconnectFailReason = 74
	DisconnectReasonEmptyAuthFromDiscovery                             protocol.ConnectionDisconnectFailReason = 75
	DisconnectReasonEmptyUrlFromDiscovery                              protocol.ConnectionDisconnectFailReason = 76
	DisconnectReasonExpiredAuthFromDiscovery                           protocol.ConnectionDisconnectFailReason = 77
	DisconnectReasonUnknownSignalServiceSignInFailure                  protocol.ConnectionDisconnectFailReason = 78
	DisconnectReasonXBLJoinLobbyFailure                                protocol.ConnectionDisconnectFailReason = 79
	DisconnectReasonUnspecifiedClientInstanceDisconnection             protocol.ConnectionDisconnectFailReason = 80
	DisconnectReasonNetherNetSessionNotFound                           protocol.ConnectionDisconnectFailReason = 81
	DisconnectReasonNetherNetCreatePeerConnection                      protocol.ConnectionDisconnectFailReason = 82
	DisconnectReasonNetherNetICE                                       protocol.ConnectionDisconnectFailReason = 83
	DisconnectReasonNetherNetConnectRequest                            protocol.ConnectionDisconnectFailReason = 84
	DisconnectReasonNetherNetConnectResponse                           protocol.ConnectionDisconnectFailReason = 85
	DisconnectReasonNetherNetNegotiationTimeout                        protocol.ConnectionDisconnectFailReason = 86
	DisconnectReasonNetherNetInactivityTimeout                         protocol.ConnectionDisconnectFailReason = 87
	DisconnectReasonStaleConnectionBeingReplaced                       protocol.ConnectionDisconnectFailReason = 88
	ConnectionDisconnectFailReasonRealmsSessionNotFound                protocol.ConnectionDisconnectFailReason = 89
	DisconnectReasonBadPacket                                          protocol.ConnectionDisconnectFailReason = 90
	DisconnectReasonNetherNetFailedToCreateOffer                       protocol.ConnectionDisconnectFailReason = 91
	DisconnectReasonNetherNetFailedToCreateAnswer                      protocol.ConnectionDisconnectFailReason = 92
	DisconnectReasonNetherNetFailedToSetLocalDescription               protocol.ConnectionDisconnectFailReason = 93
	DisconnectReasonNetherNetFailedToSetRemoteDescription              protocol.ConnectionDisconnectFailReason = 94
	DisconnectReasonNetherNetNegotiationTimeoutWaitingForResponse      protocol.ConnectionDisconnectFailReason = 95
	DisconnectReasonNetherNetNegotiationTimeoutWaitingForAccept        protocol.ConnectionDisconnectFailReason = 96
	DisconnectReasonNetherNetIncomingConnectionIgnored                 protocol.ConnectionDisconnectFailReason = 97
	DisconnectReasonNetherNetSignalingParsingFailure                   protocol.ConnectionDisconnectFailReason = 98
	DisconnectReasonNetherNetSignalingUnknownError                     protocol.ConnectionDisconnectFailReason = 99
	DisconnectReasonNetherNetSignalingUnicastDeliveryFailed            protocol.ConnectionDisconnectFailReason = 100
	DisconnectReasonNetherNetSignalingBroadcastDeliveryFailed          protocol.ConnectionDisconnectFailReason = 101
	DisconnectReasonNetherNetSignalingGenericDeliveryFailed            protocol.ConnectionDisconnectFailReason = 102
	DisconnectReasonEditorMismatchEditorWorld                          protocol.ConnectionDisconnectFailReason = 103
	DisconnectReasonEditorMismatchVanillaWorld                         protocol.ConnectionDisconnectFailReason = 104
	DisconnectReasonWorldTransferNotPrimaryClient                      protocol.ConnectionDisconnectFailReason = 105
	DisconnectReasonRequestServerShutdown                              protocol.ConnectionDisconnectFailReason = 106
	DisconnectReasonClientGameSetupCancelled                           protocol.ConnectionDisconnectFailReason = 107
	DisconnectReasonClientGameSetupFailed                              protocol.ConnectionDisconnectFailReason = 108
	ConnectionDisconnectFailReasonNoVenue                              protocol.ConnectionDisconnectFailReason = 109
	DisconnectReasonNetherNetSignalingSigninFailed                     protocol.ConnectionDisconnectFailReason = 110
	DisconnectReasonSessionAccessDenied                                protocol.ConnectionDisconnectFailReason = 111
	DisconnectReasonServiceSigninIssue                                 protocol.ConnectionDisconnectFailReason = 112
	DisconnectReasonNetherNetNoSignalingChannel                        protocol.ConnectionDisconnectFailReason = 113
	DisconnectReasonNetherNetNotLoggedIn                               protocol.ConnectionDisconnectFailReason = 114
	DisconnectReasonNetherNetClientSignalingError                      protocol.ConnectionDisconnectFailReason = 115
	DisconnectReasonSubClientLoginDisabled                             protocol.ConnectionDisconnectFailReason = 116
	DisconnectReasonDeepLinkTryingToOpenDemoWorldWhileSignedIn         protocol.ConnectionDisconnectFailReason = 117
	DisconnectReasonAsyncJoinTaskDenied                                protocol.ConnectionDisconnectFailReason = 118
	DisconnectReasonRealmsTimelineRequired                             protocol.ConnectionDisconnectFailReason = 119
	DisconnectReasonGuestWithoutHost                                   protocol.ConnectionDisconnectFailReason = 120
	DisconnectReasonFailedToJoinExperience                             protocol.ConnectionDisconnectFailReason = 121
	DisconnectReasonNetherNetDataChannelClosed                         protocol.ConnectionDisconnectFailReason = 122
	DisconnectReasonDiscoveryEnvironmentMismatch                       protocol.ConnectionDisconnectFailReason = 123
	DisconnectReasonHostWithoutKeys                                    protocol.ConnectionDisconnectFailReason = 124
	DisconnectReasonHostSignedOut                                      protocol.ConnectionDisconnectFailReason = 125
	DisconnectReasonScriptWatchdogException                            protocol.ConnectionDisconnectFailReason = 126
	DisconnectReasonScriptMemoryLimitExceeded                          protocol.ConnectionDisconnectFailReason = 127
	DisconnectReasonStorageLowDuringGameplay                           protocol.ConnectionDisconnectFailReason = 128
	DisconnectReasonStorageFullDuringGameplay                          protocol.ConnectionDisconnectFailReason = 129
	DisconnectReasonLevelStorageCorruption                             protocol.ConnectionDisconnectFailReason = 130
	DisconnectReasonEditionMismatchVanillaToEdu                        protocol.ConnectionDisconnectFailReason = 131
	DisconnectReasonEditionMismatchEduToVanilla                        protocol.ConnectionDisconnectFailReason = 132
	DisconnectReasonEditorMismatchEditorToVanilla                      protocol.ConnectionDisconnectFailReason = 133
	DisconnectReasonEditorMismatchVanillaToEditor                      protocol.ConnectionDisconnectFailReason = 134
	DisconnectReasonDenyListed                                         protocol.ConnectionDisconnectFailReason = 135
	DisconnectReasonNonceMissing                                       protocol.ConnectionDisconnectFailReason = 136
	DisconnectReasonNonceNotFound                                      protocol.ConnectionDisconnectFailReason = 137
	DisconnectReasonNonceExpired                                       protocol.ConnectionDisconnectFailReason = 138
	DisconnectReasonNonceNotValid                                      protocol.ConnectionDisconnectFailReason = 139
	DisconnectReasonHostDisconnected                                   protocol.ConnectionDisconnectFailReason = 140
	DisconnectReasonEditorJoinIntentPolicyFailure                      protocol.ConnectionDisconnectFailReason = 141
	DisconnectReasonNetherNetIdentityNotAllowed                        protocol.ConnectionDisconnectFailReason = 142
	DisconnectReasonInvalidName                                        protocol.ConnectionDisconnectFailReason = 143
	DisconnectReasonExpiredToken                                       protocol.ConnectionDisconnectFailReason = 144
	DisconnectReasonHostAcceptsNoTypeOfAuth                            protocol.ConnectionDisconnectFailReason = 145
	DisconnectReasonNotAuthenticatedFastFail                           protocol.ConnectionDisconnectFailReason = 146
	DisconnectReasonEditorNotAllowed                                   protocol.ConnectionDisconnectFailReason = 147
)

// Disconnect may be sent by the server to disconnect the client using an optional message to send as the
// disconnect screen.
type Disconnect struct {
	// Reason is the reason for the disconnection. This affects the error code displayed on the Ore UI
	// disconnection screen and is one of the constants above.
	Reason   protocol.ConnectionDisconnectFailReason
	Messages protocol.DisconnectMessages
}

// ID ...
func (*Disconnect) ID() uint32 {
	return IDDisconnect
}

func (pk *Disconnect) Marshal(io protocol.IO) {
	pk.Reason.Marshal(io)
	protocol.MarshalDisconnectMessages(io, &pk.Messages)
}
