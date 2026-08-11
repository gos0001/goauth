// Package migrations embeds the SQL migration files into the binary.
//
// It lives in the migrations directory itself because go:embed cannot reach
// outside its own package directory. Embedding them is what lets the published
// container image create its own schema: the image ships one static binary, so
// anything not compiled into it simply is not there at runtime.
//
// The same files are still applied by the `migrate` CLI in the Makefile during
// local development, and both paths write the same schema_migrations table, so
// they cannot disagree about what has been applied.
package migrations

import (
	"embed"
	"io/fs"

	"github.com/google/wire"
)

//go:embed *.sql
var files embed.FS

// FS returns the embedded migration files.
func FS() fs.FS { return files }

var Set = wire.NewSet(FS)
