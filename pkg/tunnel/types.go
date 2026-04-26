package tunnel

// TunnelOptions defines the parameters for establishing a post-quantum L4 tunnel.
type TunnelOptions struct {
	RemoteEndpoint string `json:"remote_endpoint"`
	LocalProxyPort int    `json:"local_proxy_port"`
	PublicKey      []byte `json:"public_key"`
	PQPublicKey    []byte `json:"pq_public_key"`
	Passphrase     []byte `json:"passphrase,omitempty"`
}

// TunnelStatus represents the current state of an active L4 tunnel.
type TunnelStatus struct {
	Active         bool   `json:"active"`
	LocalAddress   string `json:"local_address,omitempty"`
	RemoteEndpoint string `json:"remote_endpoint,omitempty"`
	BytesSent      int64  `json:"bytes_sent"`
	BytesReceived  int64  `json:"bytes_received"`
	HandshakeTime  string `json:"handshake_time,omitempty"`
}

// TunnelConfig provides governed tuning for the gateway.
type TunnelConfig struct {
	MaxStreams       int `json:"max_streams" mapstructure:"max_streams"`
	IdleTimeout      int `json:"idle_timeout_sec" mapstructure:"idle_timeout_sec"`
	HandshakeTimeout int `json:"handshake_timeout_sec" mapstructure:"handshake_timeout_sec"`
}
