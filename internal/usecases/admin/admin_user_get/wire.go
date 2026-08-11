package admin_user_get

import "github.com/google/wire"

var Set = wire.NewSet(New, NewHTTPv1)
