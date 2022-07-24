package tolerant

import (
	"fmt"

	"github.com/google/logger"
	"github.com/ufcg-lsd/arrebol-pb/arrebol/auth/token"
	"github.com/ufcg-lsd/arrebol-pb/arrebol/service/errors"
)

type Authorizer struct{}

func GenerateAuthorizer() *Authorizer {
	logger.Infof("Tolerant Authorizer generated")
	return &Authorizer{}
}

func (a *Authorizer) Authorize(token *token.Token) (err error) {
	if token.IsValid() {
		wID, err := token.GetWorkerId()
		if err != nil {
			msg := fmt.Sprintf("Unable to retrieve workerId: %s\n", err.Error())
			logger.Errorf(msg)
			return errors.New(msg)
		}
		logger.Infof("Token [%s] is valid\n Worker [%s] authorized\n", token.String(), wID)
	}
	return err
}
