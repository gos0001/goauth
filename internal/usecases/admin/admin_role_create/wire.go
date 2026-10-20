package admin_role_create

import "github.com/google/wire"

var Set = wire.NewSet(New, NewHTTPv1)
