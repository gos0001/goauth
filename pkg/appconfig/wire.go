package appconfig

import "github.com/google/wire"

// Set provides the parsed configuration file. The path comes in as the
// InitializeApp parameter, so there is nothing to provide here beyond Load.
var Set = wire.NewSet(Load)
