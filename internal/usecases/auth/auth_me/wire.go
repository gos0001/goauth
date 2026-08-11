package auth_me

import "github.com/google/wire"

var Set = wire.NewSet(New, NewHTTPv1)
