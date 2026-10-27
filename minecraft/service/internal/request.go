package internal

import "time"

// CatalogCallTimeout bounds discovery and catalog calls, including authentication and retries.
const CatalogCallTimeout = 40 * time.Second

// CatalogRequestTimeout bounds each HTTP attempt, including reading its response body.
const CatalogRequestTimeout = 10 * time.Second

// CatalogRequestAttempts allows a retry while staying inside the call deadline.
const CatalogRequestAttempts = 2
