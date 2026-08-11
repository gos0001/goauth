package admin_v1

import "github.com/google/wire"

var Set = wire.NewSet(NewHandlers, NewRouter)
