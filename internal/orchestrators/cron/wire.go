package cron

import "github.com/google/wire"

var Set = wire.NewSet(New)
