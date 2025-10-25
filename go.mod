module github.com/sandertv/gophertunnel

go 1.24

require (
	github.com/df-mc/go-playfab v0.0.0-00010101000000-000000000000
  github.com/df-mc/go-xsapi v1.0.1
	github.com/df-mc/jsonc v1.0.5
	github.com/go-gl/mathgl v1.2.0
	github.com/go-jose/go-jose/v4 v4.1.0
	github.com/golang/snappy v0.0.4
	github.com/google/uuid v1.6.0
	github.com/klauspost/compress v1.17.11
	github.com/pelletier/go-toml v1.9.5
	github.com/pion/logging v0.2.2
	github.com/pion/webrtc/v4 v4.0.0-beta.29.0.20240826201411-3147b45f9db5
	github.com/sandertv/go-raknet v1.14.1
	golang.org/x/net v0.27.0
	golang.org/x/oauth2 v0.21.0
	golang.org/x/text v0.17.0
)

require (
	github.com/pion/datachannel v1.5.9 // indirect
	github.com/pion/dtls/v3 v3.0.2 // indirect
	github.com/pion/ice/v4 v4.0.1 // indirect
	github.com/pion/interceptor v0.1.30 // indirect
	github.com/pion/mdns/v2 v2.0.7 // indirect
	github.com/pion/randutil v0.1.0 // indirect
	github.com/pion/rtcp v1.2.14 // indirect
	github.com/pion/rtp v1.8.9 // indirect
	github.com/pion/sctp v1.8.33 // indirect
	github.com/pion/sdp/v3 v3.0.9 // indirect
	github.com/pion/srtp/v3 v3.0.3 // indirect
	github.com/pion/stun/v3 v3.0.0 // indirect
	github.com/pion/transport/v3 v3.0.7 // indirect
	github.com/pion/turn/v4 v4.0.0 // indirect
	github.com/wlynxg/anet v0.0.3 // indirect
	golang.org/x/crypto v0.26.0 // indirect
	golang.org/x/image v0.17.0 // indirect
	golang.org/x/sys v0.24.0 // indirect
)

replace (
  replace github.com/df-mc/go-nethernet => github.com/lumineproxy/go-nethernet v0.0.0-20251024044000-f3860133179b
	github.com/df-mc/go-playfab => github.com/lactyy/go-playfab v0.0.0-20240911042657-037f6afe426f
)
