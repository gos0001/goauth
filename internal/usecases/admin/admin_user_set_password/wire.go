package admin_user_set_password

import "github.com/google/wire"

var Set = wire.NewSet(LoadConfig, New, NewHTTPv1)
