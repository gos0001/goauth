package auth_password_change

import "github.com/google/wire"

var Set = wire.NewSet(LoadConfig, New, NewHTTPv1)
