package admin_user_create

import "github.com/google/wire"

var Set = wire.NewSet(LoadConfig, New, NewHTTPv1)
