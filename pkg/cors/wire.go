package cors

import "github.com/google/wire"

var Set = wire.NewSet(LoadConfig, New)
