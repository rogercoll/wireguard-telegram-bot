use std::collections::HashMap;

pub struct LocalEndpoint {
    pub public_key: String,
    pub private_key: String,
    pub local_port: u16,
    pub persistent_keepalive: bool,
}

pub struct RemoteEndpoint {
    pub public_key: String,
    pub remote_ip: Option<String>,
    pub remote_port: Option<u16>,
    pub allowed_ips: String,
    pub latest_handshake: u64,
    pub sent_bytes: u128,
    pub received_bytes: u128,
    pub persistent_keepalive: bool,
}

pub(crate) enum Endpoint {
    Local(LocalEndpoint),
    Remote(RemoteEndpoint),
}

pub(crate) struct WireGuard {
    pub interfaces: HashMap<String, Vec<Endpoint>>,
}
