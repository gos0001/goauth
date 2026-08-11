package auth_revoke

import "github.com/google/wire"

var Set = wire.NewSet(New, NewHTTPv1)
