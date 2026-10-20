package seed_roles

import "github.com/google/wire"

var Set = wire.NewSet(New, LoadConfig)
