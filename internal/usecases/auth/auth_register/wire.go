package auth_register

import "github.com/google/wire"

var Set = wire.NewSet(LoadConfig, New, NewHTTPv1)
