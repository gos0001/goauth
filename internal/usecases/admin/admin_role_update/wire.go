package admin_role_update

import "github.com/google/wire"

var Set = wire.NewSet(New, NewHTTPv1)
