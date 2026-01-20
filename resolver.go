package anotherspf

import (
	"context"
	"net"
)

type DefaultResolver struct{}

func NewDefaultResolver() *DefaultResolver {
	return &DefaultResolver{}
}

func (d *DefaultResolver) LookupTXT(ctx context.Context, host string) ([]string, error) {
	return net.LookupTXT(host)
}

func (d *DefaultResolver) LookupIP(ctx context.Context, host string) ([]net.IP, error) {
	return net.LookupIP(host)
}

func (d *DefaultResolver) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	return net.LookupMX(name)
}
