use std::net::{SocketAddr, UdpSocket, Ipv4Addr};
use std::time::Duration;

const MULTICAST_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const DISCOVERY_PORT: u16 = 5353;
const SERVICE_NAME: &str = "_pwdcrack._tcp.local.";
const BUF_SIZE: usize = 512;

pub struct NodeDiscovery;

impl NodeDiscovery {
    pub fn advertise(node_name: &str, port: u16, is_master: bool) -> Option<()> {
        let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
        sock.set_multicast_ttl_v4(1).ok()?;
        let txt = if is_master { "master" } else { "worker" };
        let response = format!(
            "{} {} port={} txt={}",
            SERVICE_NAME, node_name, port, txt
        );
        let addr = SocketAddr::new(MULTICAST_ADDR.into(), DISCOVERY_PORT);
        sock.send_to(response.as_bytes(), addr).ok()?;
        log::info!("Advertised {} as {} on port {}", node_name, txt, port);
        Some(())
    }

    pub fn discover(timeout: Duration) -> Vec<(String, SocketAddr, bool)> {
        let sock = UdpSocket::bind(format!("0.0.0.0:{}", DISCOVERY_PORT))
            .or_else(|_| UdpSocket::bind("0.0.0.0:0"))
            .ok();
        let sock = match sock {
            Some(s) => s,
            None => return Vec::new(),
        };
        let _ = sock.set_read_timeout(Some(timeout));
        let _ = sock.join_multicast_v4(&MULTICAST_ADDR, &Ipv4Addr::UNSPECIFIED);

        let probe = format!("_pwdcrack._tcp.local. query");
        let addr = SocketAddr::new(MULTICAST_ADDR.into(), DISCOVERY_PORT);
        let _ = sock.send_to(probe.as_bytes(), addr);

        let mut nodes = Vec::new();
        let mut buf = [0u8; BUF_SIZE];
        loop {
            match sock.recv_from(&mut buf) {
                Ok((n, src)) => {
                    let raw = String::from_utf8_lossy(&buf[..n]);
                    let parts: Vec<&str> = raw.trim().split_whitespace().collect();
                    if parts.len() >= 2 && parts[0] == SERVICE_NAME {
                        let name = parts[1].to_string();
                        let is_master = parts.iter().any(|p| *p == "txt=master");
                        nodes.push((name, SocketAddr::new(src.ip(), DISCOVERY_PORT), is_master));
                    }
                }
                Err(_) => break,
            }
        }
        log::info!("Discovered {} pwdcrack nodes", nodes.len());
        nodes
    }

    pub fn default_port() -> u16 {
        DISCOVERY_PORT
    }
}
