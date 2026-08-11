package admin_user_delete

import "github.com/google/wire"

var Set = wire.NewSet(New, NewHTTPv1)
