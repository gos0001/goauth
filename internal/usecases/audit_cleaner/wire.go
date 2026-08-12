package audit_cleaner

import "github.com/google/wire"

var Set = wire.NewSet(LoadConfig, New, NewCronJob)
