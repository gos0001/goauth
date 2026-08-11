package auth_jwks

import "github.com/google/wire"

var Set = wire.NewSet(New, NewHTTPv1)
