//go:build swgpgo_nopprof

package pprof

import (
	"context"

	"github.com/database64128/swgp-go/tslog"
)

func (*Config) newService(*tslog.Logger) (*Service, error) {
	return nil, ErrPprofDisabled
}

type service struct{}

func (service) start(context.Context) error {
	return ErrPprofDisabled
}

func (service) stop() error {
	return ErrPprofDisabled
}
