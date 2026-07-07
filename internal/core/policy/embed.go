package policy

import "embed"

//go:embed defaults/*.yaml
var defaultsFS embed.FS
