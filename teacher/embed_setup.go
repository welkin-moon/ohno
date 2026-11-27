//go:build embed_setup

package teacher

import _ "embed"

//go:embed embedded/ohno-setup.exe
var EmbeddedSetupExe []byte
