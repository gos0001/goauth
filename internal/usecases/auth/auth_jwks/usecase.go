// Package auth_jwks serves the public verification keys.
//
// This endpoint is public and unauthenticated by design. It carries only public
// keys, which verify signatures and cannot produce them, so there is nothing
// here to protect. Publishing it is what lets consuming services validate
// tokens offline — no per-request call back to goauth, and goauth being down
// does not invalidate tokens already issued.
//
// A symmetric algorithm has no equivalent endpoint: the key would also mint
// tokens, so every consumer would need it delivered as a secret instead.
package auth_jwks

import (
	"context"

	"github.com/gos0001/goauth/pkg/token"
)

type Usecase struct {
	signer *token.Signer
}

func New(signer *token.Signer) *Usecase {
	return &Usecase{signer: signer}
}

func (uc *Usecase) Execute(_ context.Context, _ Input) (Output, error) {
	return Output{Document: uc.signer.JWKS()}, nil
}

type Input struct{}

// Output carries the pre-rendered JWKS document. It is raw bytes rather than a
// struct because the response must be the standard document itself.
type Output struct {
	Document []byte
}
