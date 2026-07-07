// Package version holds the build version, set via ldflags.
package version

// Version is set at build time via -ldflags "-X github.com/mrtc0/toolgate/version.Version=..."
var Version = "dev"
