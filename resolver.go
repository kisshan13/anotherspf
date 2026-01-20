package anotherspf

import "net"

type DefaultResolver struct{}

func NewDefaultResolver() *DefaultResolver {
	return &DefaultResolver{}
}

func (d *DefaultResolver) LookupTXT(host string) ([]string, error) {
	return net.LookupTXT(host)
}

func (d *DefaultResolver) LookupIP(host string) ([]net.IP, error) {
	return net.LookupIP(host)
}

func (d *DefaultResolver) LookupMX(name string) ([]*net.MX, error) {
	return net.LookupMX(name)
}
