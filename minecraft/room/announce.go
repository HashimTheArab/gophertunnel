package room

import "context"

// Announcer publishes a world's Status to an external service, such as the Xbox Live Multiplayer
// Session Directory (MPSD) through XBLAnnouncer.
type Announcer interface {
	// Announce sends the given Status to an external service for reporting.
	// The [context.Context] may be used to control the deadline and cancellation
	// of announcement. An error may be returned, if the Status could not be announced.
	Announce(ctx context.Context, status Status) error

	Close() error
}
