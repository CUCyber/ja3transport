package ja3transport

// NewTransport creates an http.Transport which mocks the given JA3 signature when HTTPS is used
func NewTransport(ja3 string) (*http.Transport, error) {
	return NewTransportWithConfig(ja3, &tls.Config{})
}

// NewTransportWithConfig creates an http.Transport object given a utls.Config
func NewTransportWithConfig(ja3 string, config *tls.Config) (*http.Transport, error) {
	spec, err := stringToSpec(ja3)
	if err != nil {
		return nil, err
	}

	dialtls := func(network, addr string) (net.Conn, error) {
		dialConn, err := net.Dial(network, addr)
		if err != nil {
			return nil, err
		}

		config.ServerName = strings.Split(addr, ":")[0]

		uTlsConn := tls.UClient(dialConn, config, tls.HelloCustom)
		if err := uTlsConn.ApplyPreset(spec); err != nil {
			return nil, err
		}
		if err := uTlsConn.Handshake(); err != nil {
			return nil, err
		}
		return uTlsConn, nil
	}

	return &http.Transport{DialTLS: dialtls}, nil
}
