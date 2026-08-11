package admin_user_list

import "github.com/google/wire"

var Set = wire.NewSet(New, NewHTTPv1)
