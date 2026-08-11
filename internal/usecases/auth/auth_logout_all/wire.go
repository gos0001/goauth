package auth_logout_all

import "github.com/google/wire"

var Set = wire.NewSet(New, NewHTTPv1)
