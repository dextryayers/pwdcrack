use std::time::Duration;
use tokio::net::TcpStream;
use tokio::io::AsyncWriteExt;
use tokio::time;

use crate::protocol::Message;

async fn write_msg(stream: &mut TcpStream, msg: &Message) -> Result<(), String> {
    let data = serde_json::to_vec(msg).map_err(|e| e.to_string())?;
    let len = (data.len() as u32).to_be_bytes();
    stream.write_all(&len).await.map_err(|e| e.to_string())?;
    stream.write_all(&data).await.map_err(|e| e.to_string())?;
    Ok(())
}

pub struct WorkerNode {
    pub master_addr: String,
    pub node_name: String,
    pub stream: Option<TcpStream>,
}

impl WorkerNode {
    pub fn new(master_addr: &str) -> Self {
        WorkerNode {
            master_addr: master_addr.to_string(),
            node_name: crate::hostname(),
            stream: None,
        }
    }

    pub async fn connect(&mut self) -> Result<(), String> {
        let stream = TcpStream::connect(&self.master_addr).await.map_err(|e| e.to_string())?;
        log::info!("Connected to master at {}", self.master_addr);
        self.stream = Some(stream);
        Ok(())
    }

    pub async fn send_handshake(&mut self) -> Result<(), String> {
        let stream = self.stream.as_mut().unwrap();
        let handshake = Message::Handshake {
            node_name: self.node_name.clone(),
            tier: std::env::consts::ARCH.to_string(),
            caps: crate::protocol::Capabilities {
                simd: "detect".to_string(),
                gpu: false,
                fpga: false,
                max_threads: std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4),
                ram_mb: 4096,
            },
        };
        write_msg(stream, &handshake).await?;
        log::info!("Sent handshake as '{}'", self.node_name);
        Ok(())
    }

    pub async fn send_heartbeat(&mut self) -> Result<(), String> {
        let stream = self.stream.as_mut().unwrap();
        let hb = Message::Heartbeat {
            node_name: self.node_name.clone(),
            stats: crate::protocol::WorkerStats {
                hashes_sec: 0.0,
                total_cracked: 0,
                power_watts: 0.0,
                temperature_c: 0.0,
            },
        };
        write_msg(stream, &hb).await?;
        Ok(())
    }

    pub async fn run_worker_loop(&mut self) -> Result<(), String> {
        self.connect().await?;
        self.send_handshake().await?;

        let mut interval = time::interval(Duration::from_secs(5));
        loop {
            interval.tick().await;
            self.send_heartbeat().await?;
        }
    }
}
