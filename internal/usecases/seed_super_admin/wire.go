package seed_super_admin

import "github.com/google/wire"

var Set = wire.NewSet(LoadConfig, New)
