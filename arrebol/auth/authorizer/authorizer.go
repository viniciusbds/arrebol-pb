package authorizer

import (
	"os"
	"strconv"

	"github.com/google/logger"
	"github.com/ufcg-lsd/arrebol-pb/arrebol/auth/authorizer/policy/allowlist"
	"github.com/ufcg-lsd/arrebol-pb/arrebol/auth/authorizer/policy/tolerant"
	"github.com/ufcg-lsd/arrebol-pb/arrebol/auth/token"
)

const AllowAllKey = "ALLOW_ALL"

type Authorizer interface {
	Authorize(token *token.Token) error
}

func NewAuthorizer() Authorizer {
	allow, err := strconv.ParseBool(os.Getenv(AllowAllKey))

	if err != nil {
		logger.Fatalf("Cannot understand the flag: %s", err.Error())
	}

	if allow {
		return allowlist.GenerateAuthorizer()
	}
	return tolerant.GenerateAuthorizer()
}

func GetNextAvailableWorkerID() string {
	return allowlist.GenerateAuthorizer().AllowList.GetNextAvailableWorkerID()
}
