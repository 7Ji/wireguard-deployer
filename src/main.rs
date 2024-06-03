use std::{collections::{BTreeMap, HashMap}, fs::{create_dir, create_dir_all, remove_dir_all, File}, io::{Read, Write}, mem::MaybeUninit, net::IpAddr, os::unix::fs::MetadataExt, path::{Path, PathBuf}};
use base64::Engine;
use rand::RngCore;
use serde::Deserialize;
use ipnet::IpNet;

const WIREGUARD_KEY_LENGTH: usize = 32;
const WIREGUARD_KEY_BASE64_LENGTH: usize = 44;

struct WireGuardKey {
    value: [u8; WIREGUARD_KEY_LENGTH]
}

impl WireGuardKey {
    fn new() -> Self {
        let mut value = [0; WIREGUARD_KEY_LENGTH];
        rand::thread_rng().fill_bytes(&mut value);
        Self { value }
    }

    fn base64(&self) -> [u8; WIREGUARD_KEY_BASE64_LENGTH] {
        let mut result = [0; WIREGUARD_KEY_BASE64_LENGTH];
        let size = base64::engine::general_purpose::STANDARD
            .encode_slice(&self.value, &mut result)
            .expect("Failed to format base64 string");
        if size != WIREGUARD_KEY_BASE64_LENGTH {
            panic!("Formatted base64 string length not right")
        }
        result
    }

    fn pubkey(&self) -> Self {
        let value = curve25519_dalek::EdwardsPoint::mul_base_clamped(self.value).to_montgomery().to_bytes();
        Self { value }
    }

    fn to_file(&self, key_file: &Path) {
        File::create(key_file).expect("Failed to create key file")
            .write_all(&self.base64()).expect("Failed to write key file");
    }

    fn from_file(key_file: &Path) -> Self {
        let metadata = key_file.symlink_metadata().expect("Failed to read metadata");
        if ! metadata.is_file() {
            panic!("Existing key is not file")
        }
        if metadata.size() as usize != WIREGUARD_KEY_BASE64_LENGTH {
            panic!("Existing key file size not right")
        }
        let mut encoded = [0; WIREGUARD_KEY_BASE64_LENGTH];
        File::open(key_file).expect("Failed to open file")
            .read_exact(&mut encoded).expect("Failed to read key from file");
        let mut value = [0; WIREGUARD_KEY_LENGTH];
        base64::engine::general_purpose::STANDARD
            .decode_slice(&encoded, &mut value)
            .expect("Failed to decode base64 string");
        Self { value }
    }

    fn generate_to_file_lazy(key_file: &Path) -> Self {
        if key_file.exists() {
            return Self::from_file(key_file)
        }
        let key = Self::new();
        key.to_file(key_file);
        key

    }
}

#[derive(Debug, Deserialize)]
struct PeerConfig {
    ip: IpNet,
    #[serde(default)]
    allow: Vec<IpNet>,
    #[serde(default)]
    endpoint: String,
}

#[derive(Debug, Deserialize)]
struct Config {
    #[serde(default)]
    psk: bool,
    netdev: String,
    network: String,
    iface: String,
    peers: BTreeMap<String, PeerConfig>,
}

fn content_to_file<C: AsRef<[u8]>>(content: C, file: &Path) {
    File::create(file).expect("Failed to open file").write_all(content.as_ref()).expect("Failed to write");
}

impl Config {
    fn finalize(&mut self) {
        if ! self.netdev.ends_with(".netdev") {
            self.netdev.push_str(".netdev")
        }
        if ! self.network.ends_with(".network") {
            self.network.push_str(".network")
        }
    }
    fn write(&self, folder: &Path) {
        let dir_keys = folder.join("keys");
        create_dir_all(&dir_keys).expect("Failed to create keys folder");
        let mut psks = HashMap::new();
        if self.psk {
            let mut names: Vec<&String> = self.peers.keys().collect();
            names.sort_unstable();
            for i in 0..self.peers.len() {
                for j in i+1..self.peers.len() {
                    let some = names[i];
                    let other = names[j];
                    let key = WireGuardKey::generate_to_file_lazy(&dir_keys.join(format!("psk-{}-{}", some, other)));
                    let _ = psks.insert((some, other), key);
                }
            }
        }
        let mut keys = HashMap::new();
        for (peer_name, peer_config) in self.peers.iter() {
            let key_peer = WireGuardKey::generate_to_file_lazy(&dir_keys.join(format!("private-{}", peer_name)));
            let pubkey_peer = key_peer.pubkey();
            keys.insert(peer_name, (key_peer, pubkey_peer));
        }

        let configs = folder.join("configs");
        let _ = remove_dir_all(&configs);
        create_dir_all(&configs).expect("Failed to create configs folder");
        let mut buffer_netdev = format!("[NetDev]\nName={}\nKind=wireguard\n\n[WireGuard]\nListenPort=51820\nPrivateKeyFile=/etc/systemd/network/.keys/wg/", self.iface);
        let len_buffer_netdev = buffer_netdev.len();
        let mut buffer_network = format!("[Match]\nName={}\n\n", self.iface);
        let len_buffer_network = buffer_network.len();
        for (peer_name, peer_config) in self.peers.iter() {
            let config = configs.join(peer_name);
            create_dir(&config).expect("Failed to create config folder");
            buffer_netdev.truncate(len_buffer_netdev);
            buffer_network.truncate(len_buffer_network);
            buffer_netdev.push_str(&peer_name);
            buffer_netdev.push_str(".key\n");
            // let (key_peer, pubkey_peer) = keys.get(peer_name).expect("Failed to look up peer key");
            for (endpoint_name, endpoint_config) in self.peers.iter() {
                if peer_name == endpoint_name {
                    continue
                }
                let (key_endpoint, pubkey_endpoint) = keys.get(endpoint_name).expect("Failed to look up endpoint key");
                buffer_netdev.push_str(&format!("\n[WireGuardPeer]\nPublicKey={}\nAllowedIPs={}\n", String::from_utf8_lossy(&pubkey_endpoint.base64()), endpoint_config.ip));
                if ! endpoint_config.endpoint.is_empty() {
                    buffer_netdev.push_str(&format!("Endpoint={}", endpoint_config.endpoint))
                }
            }
            content_to_file(&buffer_netdev, &config.join(&self.netdev));
            content_to_file(&buffer_network, &config.join(&self.network))
        }
    }
}

fn main() { // arg1: config file, arg2: output dir
    let mut args = std::env::args_os();
    let config = args.nth(1).expect("Failed to get first argument for config file path");
    let output = args.next().expect("Faield to get second argument for output folder");
    let file = File::open(config).expect("Failed to open config file");
    let mut config: Config = serde_yaml::from_reader(file).expect("Failed to parse YAML");
    config.finalize();
    config.write(&PathBuf::from(output));
}
