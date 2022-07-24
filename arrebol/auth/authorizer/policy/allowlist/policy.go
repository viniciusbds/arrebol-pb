package allowlist

import (
	"fmt"

	"github.com/google/logger"
	"github.com/ufcg-lsd/arrebol-pb/arrebol/auth/token"
	"github.com/ufcg-lsd/arrebol-pb/arrebol/service/errors"
)

type Authorizer struct {
	AllowList AllowList
}

func GenerateAuthorizer() *Authorizer {
	logger.Infof("Allowlist Authorizer generated")
	return &Authorizer{AllowList: NewAllowList()}
}

func (auth *Authorizer) Authorize(token *token.Token) error {
	// TODO authorize token
	var (
		err      error
		workerId string
	)

	if token.IsValid() {
		workerId, err = token.GetWorkerId()
		if err != nil {
			msg := fmt.Sprintf("Error getting the workerID from token %v\n", token.String())
			logger.Errorf(msg)
			return errors.New(msg)
		}
		if contains := auth.AllowList.contains(workerId); !contains {
			msg := fmt.Sprintf("The worker [%s] is not in the allowlist\n", workerId)
			logger.Errorf(msg)
			return errors.New(msg)
		}
	}
	logger.Infof("Token [%s] authorized\n", token.String())
	return err
}
