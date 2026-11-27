//go:build !embed_setup

package teacher

// EmbeddedSetupExe is empty unless built with -tags embed_setup.
var EmbeddedSetupExe []byte
