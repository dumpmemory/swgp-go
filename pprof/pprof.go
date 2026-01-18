package pprof

import (
	"context"
	"log/slog"

	"github.com/database64128/swgp-go/tslog"
)

// PprofDisabledError is returned when the pprof service is disabled at build time.
type PprofDisabledError struct{}

func (PprofDisabledError) Error() string {
	return "pprof service is disabled at build time"
}

var ErrPprofDisabled = PprofDisabledError{}

// Config is the configuration for the pprof service.
type Config struct {
	// Enabled controls whether the pprof service is enabled.
	Enabled bool `json:"enabled"`

	// ListenNetwork is the network to listen on.
	ListenNetwork string `json:"listenNetwork,omitzero"`

	// ListenAddress is the address to listen on.
	ListenAddress string `json:"listenAddress"`
}

// NewService creates a new pprof service.
func (c *Config) NewService(logger *tslog.Logger) (*Service, error) {
	return c.newService(logger)
}

// Service implements [service.Service].
type Service struct {
	service
}

// SlogAttr implements [service.Service.SlogAttr].
func (*Service) SlogAttr() slog.Attr {
	return slog.String("service", "pprof")
}

// Start implements [service.Service.Start].
func (s *Service) Start(ctx context.Context) error {
	return s.start(ctx)
}

// Stop implements [service.Service.Stop].
func (s *Service) Stop() error {
	return s.stop()
}
