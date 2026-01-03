package anotherspf

import "net"

type defaultResolver struct{}

func (d *defaultResolver) LookupTXT(host string) ([]string, error) {
	return net.LookupTXT(host)
}

func (d *defaultResolver) LookupIP(host string) ([]net.IP, error) {
	return net.LookupIP(host)
}

func (d *defaultResolver) LookupMX(name string) ([]*net.MX, error) {
	return net.LookupMX(name)
}
