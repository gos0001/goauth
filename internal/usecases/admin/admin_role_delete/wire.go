package admin_role_delete

import "github.com/google/wire"

var Set = wire.NewSet(New, NewHTTPv1)
