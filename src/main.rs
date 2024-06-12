/*
sd-networkd-wg-deployed, to generate easily deployable WireGuard configs and keys for systemd-networkd
Copyright (C) 2024-present Guoxin "7Ji" Pu

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

use std::{cmp::Ordering, collections::{BTreeMap, HashMap}, fmt::Display, fs::{create_dir_all, remove_dir_all, File}, io::{Read, Write}, path::{Path, PathBuf}, str::FromStr};
use base64::Engine;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

const LEN_CURVE25519_KEY_RAW: usize = 32;
const LEN_CURVE25519_KEY_BASE64: usize = 44;

#[derive(Debug)]
enum Error {
    ArgumentNotRight,
    Base64EncodeBufferTooSmall,
    Base64LengthIncorrect {
        expected: usize, actual: usize
    },
    Base64DecodeError (String),
    Base64DecodeBufferTooSmall,
    DuplicatedRoute,
    FormatError (String),
    ImpossibleLogic,
    IoError (String),
    // TarError (String),
    YAMLError (String),
}

impl From<base64::EncodeSliceError> for Error {
    fn from(_: base64::EncodeSliceError) -> Self {
        Self::Base64EncodeBufferTooSmall
    }
}

impl From<base64::DecodeSliceError> for Error {
    fn from(value: base64::DecodeSliceError) -> Self {
        match value {
            base64::DecodeSliceError::DecodeError(e) => e.into(),
            base64::DecodeSliceError::OutputSliceTooSmall => 
                Self::Base64DecodeBufferTooSmall,
        }
    }
}

#[inline(always)]
fn string_from_display<D: Display>(display: D) -> String {
    format!("{}", display)
}

macro_rules! impl_from_error_display {
    ($external: ty, $internal: ident) => {
        impl From<$external> for Error {
            fn from(value: $external) -> Self {
                Self::$internal(string_from_display(value))
            }
        }
    };
}

impl_from_error_display!(std::io::Error, IoError);
impl_from_error_display!(serde_yaml::Error, YAMLError);
impl_from_error_display!(base64::DecodeError, Base64DecodeError);
impl_from_error_display!(std::fmt::Error, FormatError);
// impl_from_error_display!(tar::)

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::ArgumentNotRight => write!(f, "Argument not right"),
            Error::Base64EncodeBufferTooSmall => 
                write!(f, "Base64 encode buffer too small"),
            Error::Base64LengthIncorrect { expected, actual } => 
                write!(f, "Base64 length incorrect, expected {}, actual {}",
                    expected, actual),
            Error::Base64DecodeError(e) => 
                write!(f, "Base64 decode error: {}", e),
            Error::Base64DecodeBufferTooSmall => 
                write!(f, "Base64 decode buffer too small"),
            Error::DuplicatedRoute =>
                write!(f, "Duplicated route"),
            Error::FormatError(e) =>
                write!(f, "Format Error: {}", e),
            Error::ImpossibleLogic => write!(f, "Impossible logic"),
            Error::IoError(e) => write!(f, "IO Error: {}", e),
            Error::YAMLError(e) => write!(f, "YAML Error: {}", e),
        }
    }
}

type Result<T> = std::result::Result<T, Error>;

fn file_create_checked<P: AsRef<Path>>(path: P) -> Result<File> {
    File::create(&path).map_err(|e|{
        eprintln!("Failed to create file at '{}': {}", 
                    path.as_ref().display(), e);
        e.into()
    })
}

fn write_all_checked<W: Write>(writer: &mut W, data: &[u8]) -> Result<()> {
    writer.write_all(data).map_err(|e|{
        eprintln!("Failed to write {} bytes to file: {}", data.len(), e);
        e.into()
    })
}

fn file_open_checked<P: AsRef<Path>>(path: P) -> Result<File> {
    File::open(&path).map_err(|e|{
        eprintln!("Failed to open file at '{}': {}", 
                    path.as_ref().display(), e);
        e.into()
    })
}

fn read_exact_checked<R: Read>(reader: &mut R, data: &mut [u8]) -> Result<()> {
    reader.read_exact(data).map_err(|e|{
        eprintln!("Failed to read {} bytes from file: {}", data.len(), e);
        e.into()
    })
}

fn create_dir_all_checked<P: AsRef<Path>>(path: P) -> Result<()> {
    create_dir_all(&path).map_err(|e|{
        eprintln!("Failed to create dir '{}': {}", path.as_ref().display(), e);
        e.into()
    })
}

fn content_to_file<P: AsRef<Path>>(content: &[u8], path: P) -> Result<()> {
    write_all_checked(&mut file_create_checked(path)?, content)
}

fn yaml_from_reader_checked<T, R>(reader: &mut R) -> Result<T> 
where
    T: DeserializeOwned,
    R: Read
{
    serde_yaml::from_reader(reader).map_err(Into::into)
}

/// A raw WireGuard key, users shall not use this, but `WireGuardKey` instead
type WireGuardKeyRaw = [u8; WireGuardKey::LEN_RAW];
/// A base64-encoded WireGuard key
type WireGuardKeyBase64 = [u8; WireGuardKey::LEN_BASE64];

/// A WireGuard-compatible key, does not differentiate public or private by 
/// itself, user should take care of that
#[derive(Clone, Debug, Default)]
struct WireGuardKey {
    value: WireGuardKeyRaw
}

impl WireGuardKey {
    /// The length of a WireGuard key, raw byte length
    const LEN_RAW: usize = LEN_CURVE25519_KEY_RAW;
    /// The length of a WireGuard key, base64 encoded length
    const LEN_BASE64: usize = LEN_CURVE25519_KEY_BASE64;

    /// The base64 engine we use, chars `0-9` `a-z` `A-Z` `/` `+`, with padding
    const BASE64_ENGINE: base64::engine::GeneralPurpose 
        = base64::engine::general_purpose::STANDARD;

    fn new_empty_raw() -> WireGuardKeyRaw {
        [0; Self::LEN_RAW]
    }

    fn new_empty_base64() -> WireGuardKeyBase64 {
        [0; Self::LEN_BASE64]
    }

    /// Create a new random `WireGuardKey` with a `rand::Rng`-compatible 
    /// generator
    fn new_with_generator<G: rand::Rng>(mut generator: G) -> Self {
        let mut value = Self::new_empty_raw();
        generator.fill_bytes(&mut value);
        Self { value }
    }

    /// Create a new random `WireGuardKey`, with a `rand::thread_rng()` random
    /// generator
    fn new() -> Self {
        Self::new_with_generator(rand::thread_rng())
    }

    /// Encode this key to base64, note it is still raw bytes, users want a 
    /// `String` shall call `base64_string()` instead
    fn base64(&self) -> Result<WireGuardKeyBase64> {
        let mut buffer = Self::new_empty_base64();
        let size = Self::BASE64_ENGINE
            .encode_slice(&self.value, &mut buffer)?;
        if size == Self::LEN_BASE64 {
            Ok(buffer)
        } else {
            Err(Error::Base64LengthIncorrect {
                expected: Self::LEN_BASE64,
                actual: size,
            })
        }
    }

    /// Encode this key to base64 string
    fn base64_string(&self) -> String {
        let mut value = String::new();
        value.reserve_exact(Self::LEN_BASE64);
        Self::BASE64_ENGINE.encode_string(self.value, &mut value);
        value
    }

    /// Get the corresponding public key, assuming this is a private key.
    /// 
    /// As we don't differentiate on public key or private key, it's totally
    /// legal to generate a public key of a public key, but that would be of
    /// no use
    fn pubkey(&self) -> Self {
        let value = curve25519_dalek::EdwardsPoint::mul_base_clamped(
            self.value).to_montgomery().to_bytes();
        Self { value }
    }

    /// Write this key to file, without encoding
    fn _to_file_raw<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        write_all_checked(
            &mut file_create_checked(path)?, &self.value)
    }

    /// Write this key to file, base64 encoded
    fn to_file_base64<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let base64 = self.base64()?;
        write_all_checked(&mut file_create_checked(path)?, &base64)
    }

    /// Read from file, in which a key is stored base64-encoded
    fn from_file_base64<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut base64 = Self::new_empty_base64();
        read_exact_checked(
            &mut file_open_checked(path)?, &mut base64)?;
        let mut value = Self::new_empty_raw();
        Self::BASE64_ENGINE.decode_slice(&base64, &mut value)?;
        Ok( Self { value } )
    }

    /// Read from file, in which a key is stored as raw un-encoded bytes
    fn _from_file_raw<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut value = Self::new_empty_raw();
        read_exact_checked(
            &mut file_open_checked(path)?, &mut value)?;
        Ok( Self { value } )
    }

    /// Read from file if it exists, otherwise generate a new one
    fn _from_file_raw_or_new<P: AsRef<Path>>(path: P) -> Result<Self> {
        if path.as_ref().exists() {
            return Self::_from_file_raw(path)
        }
        let key = Self::new();
        key._to_file_raw(path)?;
        Ok(key)
    }

    /// Read from file if it exists, otherwise generate a new one
    fn from_file_base64_or_new<P: AsRef<Path>>(path: P) -> Result<Self> {
        if path.as_ref().exists() {
            return Self::from_file_base64(path)
        }
        let key = Self::new();
        key.to_file_base64(path)?;
        Ok(key)
    }
}

type PeerList = BTreeMap<String, PeerConfig>;

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum PeerEndpointConfig {
    Plain (String),
    Multi {
        #[serde(default, rename = "^parent")]
        parent: String,
        #[serde(default, rename = "^neighbor")]
        neighbor: String,
        #[serde(default, rename = "^child")]
        child: String,
        #[serde(flatten)]
        map: HashMap<String, String>,
    }
}

enum PeerEndpointCharacter {
    Parent,
    Neighbor,
    Child
}

impl Default for PeerEndpointConfig {
    fn default() -> Self {
        Self::Plain(Default::default())
    }
}

impl PeerEndpointConfig {
    fn get(&self, name: &str, character: PeerEndpointCharacter) -> &str {
        match self {
            PeerEndpointConfig::Plain(endpoint) => endpoint,
            PeerEndpointConfig::Multi { 
                parent, neighbor, child, 
                map 
            } => match map.get(name) {
                    Some(endpoint) => endpoint,
                    None => match character {
                        PeerEndpointCharacter::Parent => parent,
                        PeerEndpointCharacter::Neighbor => neighbor,
                        PeerEndpointCharacter::Child => child,
                    },
                },
        }
    }
}

#[derive(Debug, Deserialize)]
/// Config of a peer
struct PeerConfig {
    /// The IP of the peer inside this network
    ip: String,
    /// The .netdev unit name, without `.netdev` suffix, (the suffix would be 
    /// appended automatically), e.g. `30-wireguard`, if this is empty
    /// then the global `netdev` would be used.
    #[serde(default)]
    netdev: String,
    /// The .network unit name, without `.network` suffix, (the suffix would be 
    /// appended automatically), e.g. `40-wireguard`, if this is empty
    /// then the global `network` would be used
    #[serde(default)]
    network: String,
    /// The interface name, if this is kept empty then the global `iface` would
    /// be used
    #[serde(default)]
    iface: String,
    /// The endpoint, i.e. the IP outside this network that other peers can 
    /// connect accordingly, usually a host + port pair
    #[serde(default)]
    endpoint: PeerEndpointConfig,
    /// IP ranges outside of the main wireguard range that should be forwarded
    /// into the wireguard range
    #[serde(default)]
    forward: Vec<String>,
    /// Peer names this peer is able to connect directly in the same level
    /// - As a child, a peer is always able to connect to its parent
    /// - If not set (as `None`), this peer is able to connect to any other peer 
    /// directly at the same level
    /// - If set (as `Some`), this peer is only able to connect listed peers at
    /// the same level directly, even if it's empty, in that case it would only
    /// be able to connect to its parent directly
    direct: Option<Vec<String>>,
    /// Peer names that shall be kept alive, useful for self => NAT => target
    #[serde(default)]
    keep: Vec<String>,
    /// Child peers connected under this peer.
    /// - Peers living as child can always connect to their parent. If none of 
    /// children can connect to other peers, this is essentially a star network
    /// - Peers, if not explicitly disallowed, can connect to any other peer
    /// in the same level, this is essentially a full mesh network
    #[serde(default)]
    children: PeerList
}

const fn default_psk() -> bool {
    true
}

const fn default_mask() -> u8 {
    24
}

fn default_iface() -> String {
    "wg0".into()
}

const fn default_iface_borrowed() -> &'static str {
    "wg0"
}

const fn default_port() -> u16 {
    51820
}

#[derive(Debug, Deserialize)]
struct Config {
    /// Whether to generate pre-shared key for each peer pair
    #[serde(default = "default_psk")]
    psk: bool,
    /// The .netdev unit name, without `.netdev` suffix, (the suffix would be 
    /// appended automatically), e.g. `30-wireguard`
    netdev: String,
    /// The .network unit name, without `.network` suffix, (the suffix would be 
    /// appended automatically), e.g. `40-wireguard`
    network: String,
    /// The network subnet mask,
    #[serde(default = "default_mask")]
    mask: u8,
    /// The interface name, e.g. `wg0`
    #[serde(default = "default_iface")]
    iface: String,
    /// The default port for endpoint if an endpoint is set to advanced style
    /// but without actual port set
    #[serde(default = "default_port")]
    port: u16,
    /// The list of peers
    peers: PeerList,
}

/// A wireguard key in netdev that shall be stored in a file
#[derive(Clone, Debug, Default)]
struct NetDevKeyFile {
    /// The backing raw key
    raw: WireGuardKey,
    /// The file name this key shall be stored, inside the folder
    /// `/etc/systemd/network/keys/wg`
    name: String,
}

impl NetDevKeyFile {
    fn base64(&self) -> Result<WireGuardKeyBase64> {
        self.raw.base64()
    }
    fn _base64_string(&self) -> String {
        self.raw.base64_string()
    }
    fn from_dir_keys_or_new(dir_keys: &Path, name: String) -> Result<Self> {
        let raw = WireGuardKey::from_file_base64_or_new(dir_keys.join(&name))?;
        Ok(NetDevKeyFile { raw, name })
    }
    fn pubkey(&self) -> WireGuardKey {
        self.raw.pubkey()
    }
    fn from_dir_keys_with_pubkey_or_new(dir_keys: &Path, name: String) -> Result<(Self, WireGuardKey)> {
        let key_file = Self::from_dir_keys_or_new(dir_keys, name)?;
        let pubkey = key_file.pubkey();
        Ok((key_file, pubkey))
    }
}

#[derive(Debug, Default)]
struct NetDevPeerEndpointAddress<'a> {
    raw: &'a str,
    host: &'a str,
    v6: bool,
    port: u16
}

impl<'a> std::fmt::Display for NetDevPeerEndpointAddress<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

impl<'a> NetDevPeerEndpointAddress<'a> {
    fn is_empty(&self) -> bool {
        self.host.is_empty()
    }
    fn push_to_string(&self, buffer: &mut String) -> Result<()> {
        if self.v6 {
            buffer.push('[');
        }
        buffer.push_str(self.host);
        if self.v6 {
            buffer.push(']');
        }
        buffer.push(':');
        std::fmt::Write::write_fmt(buffer, format_args!("{}", self.port))?;
        Ok(())
    }
    fn from_str_with_port_global(value: &'a str, port_global: u16) -> Self {
        match std::net::IpAddr::from_str(value) {
            Ok(r) => Self {
                raw: value,
                host: value,
                v6: r.is_ipv6(),
                port: port_global,
            },
            Err(_) => 
                // Only possible: domain(+port), v4+port, v6+port
                match value.rsplit_once(':') {
                    Some((mut host, port)) => {
                        let port = match port.parse() {
                            Ok(port) => port,
                            Err(_) => {
                                host = value;
                                port_global
                            },
                        };
                        // Only possible: domain, v4, v6
                        if host.starts_with('[') && host.ends_with(']') {
                            let host = &host[1..host.len()-1];
                            if let Ok(std::net::IpAddr::V6(_)) = std::net::IpAddr::from_str(host) {
                                return Self {
                                    raw: value,
                                    host,
                                    v6: true,
                                    port,
                                }
                            }
                        }
                        Self {
                            raw: value,
                            host,
                            v6: false,
                            port,
                        }
                    },
                    None => Self {
                        raw: value,
                        host: value,
                        v6: false,
                        port: port_global,
                    },
                },
        }
    }
}

/// A wireguard peer in a netdev
#[derive(Debug)]
struct NetDevPeer<'a> {
    name: &'a str,
    /// The incoming IP ranges this is allowed to access, also hinting whether
    /// traffic should go through this peer if a corresponding range is found
    allowed: Vec<&'a str>,
    /// The public key of this peer
    pubkey: WireGuardKey,
    /// The endpoint
    endpoint: NetDevPeerEndpointAddress<'a>,
    /// The pre-shared key between the peer
    psk: Option<NetDevKeyFile>,
    /// Keep-alive
    keep: bool,
}

impl<'a> Default for NetDevPeer<'a> {
    fn default() -> Self {
        Self { 
            name: Default::default(), 
            allowed: Default::default(), 
            pubkey: Default::default(), 
            endpoint: Default::default(), 
            psk: Default::default(),
            keep: Default::default(),
        }
    }
}

/// A .netdev config
#[derive(Debug, Default)]
struct NetDevConfig<'a> {
    name: &'a str,
    /// The private key of the netdev
    key: NetDevKeyFile,
    /// The peers
    peers: Vec<NetDevPeer<'a>>
}

/// A .network config
#[derive(Debug, Default)]
struct NetWorkConfig<'a> {
    name: &'a str,
    address: &'a str,
    routes: Vec<&'a str>,
}

/// A .netdev + .network config
#[derive(Debug, Default)]
struct CompositeConfig<'a> {
    iface: &'a str,
    mask: u8,
    netdev: NetDevConfig<'a>,
    network: NetWorkConfig<'a>
}

#[derive(Debug, Default)]
struct ConfigsToWrite<'a> {
    map: BTreeMap<&'a str, CompositeConfig<'a>>
}

#[derive(Debug, Default)]
struct RouteInfo<'a> {
    via: &'a str,
    /// How many pseudo jumps away, this is not the actual jump.
    /// 
    /// Price of non-wireguard traffic is low:
    /// - Self: 0
    /// - Forward: 1
    /// 
    /// Price of in-wireguard traffic is higher:
    /// - Peer to neighbor: 2
    /// - Peer to parent: 3
    /// - Parent to child: 3
    /// 
    /// This is to prefer direct neighbor connection over parent-forwarding
    jump: usize, // special value 0 for self

    /// WireGuard internal IP
    internal: bool
}

type PeerWithConfig<'a> = (&'a str, &'a PeerConfig);
type RoutesMap<'a> = BTreeMap<&'a str, RouteInfo<'a>>;

#[derive(Debug, Default)]
struct RoutesInfo<'a> {
    // parent: &'a str,
    nexts: Vec<(&'a str, usize)>,
    routes: RoutesMap<'a>
}

fn vec_string_contains_str(list: &Vec<String>, value: &str) -> bool {
    for existing in list.iter() {
        if existing == value {
            return true
        }
    }
    false
}

fn can_neighbors_direct<'a>(some: PeerWithConfig<'a>, other: PeerWithConfig<'a>) -> bool {
    if let Some(direct) = &some.1.direct {
        if ! vec_string_contains_str(direct, other.0) {
            return false
        }
    }
    if let Some(direct) = &other.1.direct {
        if ! vec_string_contains_str(direct, some.0) {
            return false
        }
    }
    true
}

impl<'a> RoutesInfo<'a> {
    fn try_new(peer: PeerWithConfig<'a>, parent: Option<PeerWithConfig<'a>>, neighbors: &'a PeerList
    ) -> Result<Self>
    {
        let (parent_name, parent_config) = match parent {
            Some((parent_name, parent_config)) => (parent_name, Some(parent_config)),
            None => ("", None),
        };
        let mut routes_info = RoutesInfo {
            nexts: vec![(&parent_name, 3)],
            routes: Default::default(),
        };
        let (peer_name, peer_config) = peer;
        routes_info.try_add_from_self(peer_config)?;
        if let Some(parent_config) = parent_config {
            routes_info.try_add_from_parent(parent_name, parent_config)?
        }
        for (neighbor_name, neighbor_config) in neighbors.iter() {
            if neighbor_name == peer_name ||
             ! can_neighbors_direct(peer, (neighbor_name, neighbor_config))  
            {
                continue
            }
            routes_info.try_add_from_neighbor(neighbor_name, neighbor_config)?
        }
        routes_info.try_add_from_children(&peer_config.children)?;
        routes_info.nexts.sort_unstable();
        Ok(routes_info)
    }

    fn try_add(&mut self, target: &'a str, via: &'a str, jump: usize, internal: bool) -> Result<()> 
    {
        let route_info = RouteInfo { via, jump, internal };
        if self.routes.insert(target, route_info).is_some() {
            eprintln!("Duplicate route target '{}' for peer, please check your config to make sure all IPs, forwards are unique!", target);
            Err(Error::DuplicatedRoute)
        } else {
            Ok(())
        }
    }

    fn try_add_from_peer(
        &mut self, peer_name: &'a str, peer_config: &'a PeerConfig, jump: usize
    ) -> Result<()> 
    {
        self.try_add(&peer_config.ip, peer_name,  jump, true)?;
        for forward in peer_config.forward.iter() {
            self.try_add(&forward, peer_name, jump + 1, false)?;
        }
        Ok(())
    }

    fn try_add_from_self(
        &mut self, peer_config: &'a PeerConfig
    ) -> Result<()> 
    {
        self.try_add_from_peer("", peer_config, 0)
    }

    fn try_add_from_parent(
        &mut self, peer_name: &'a str, peer_config: &'a PeerConfig
    ) -> Result<()> 
    {
        self.try_add_from_peer(peer_name, peer_config, 3)
    }

    fn try_add_from_child(
        &mut self, peer_name: &'a str, peer_config: &'a PeerConfig
    ) -> Result<()> 
    {
        self.nexts.push((peer_name, 3));
        self.try_add_from_peer(peer_name, peer_config, 3)
    }

    fn try_add_from_children(
        &mut self, peers: &'a PeerList
    ) -> Result<()> 
    {
        for (peer_name, peer_config) in peers.iter() {
            self.try_add_from_child(peer_name, peer_config)?
        }
        Ok(())
    }

    fn try_add_from_neighbor(
        &mut self, peer_name: &'a str, peer_config: &'a PeerConfig
    ) -> Result<()> 
    {
        self.nexts.push((peer_name, 2));
        self.try_add_from_peer(peer_name, peer_config, 2)
    }
}


#[derive(Debug, Default)]
struct ConfigsToWriteParsing<'a> {
    map: BTreeMap<&'a str, (CompositeConfig<'a>, RoutesInfo<'a>)>,
    route_targets: Vec<&'a str>,
    keys: HashMap<&'a str, (NetDevKeyFile, WireGuardKey)>,
    psks: HashMap<(&'a str, &'a str), NetDevKeyFile>
}

impl<'a> ConfigsToWriteParsing<'a> {
    fn get_psk_or_new(&mut self, dir_keys: &Path, some: &'a str, other: &'a str) -> Result<&NetDevKeyFile> {
        if some.cmp(other) == Ordering::Less {
            self.get_psk_or_new_sorted(dir_keys, some, other)
        } else {
            self.get_psk_or_new_sorted(dir_keys, other, some)
        }
    }

    fn get_psk_or_new_sorted(&mut self, dir_keys: &Path, some: &'a str, other: &'a str) -> Result<&NetDevKeyFile> {
        match self.psks.entry((some, other)) {
            std::collections::hash_map::Entry::Occupied(entry) => Ok(entry.into_mut()),
            std::collections::hash_map::Entry::Vacant(entry) => 
                Ok(entry.insert(NetDevKeyFile::from_dir_keys_or_new(dir_keys, format!("pre-shared-{}-{}", some, other))?)),
        }
    }
    
    fn get_key_or_new(&mut self, dir_keys: &Path, peer: &'a str) -> Result<&(NetDevKeyFile, WireGuardKey)> 
    {
        match self.keys.entry(peer) {
            std::collections::hash_map::Entry::Occupied(entry) => Ok(entry.into_mut()),
            std::collections::hash_map::Entry::Vacant(entry) =>
                Ok(entry.insert(NetDevKeyFile::from_dir_keys_with_pubkey_or_new(dir_keys, format!("private-{}", peer))?)),
        }
    }

    fn try_add_peer(&mut self, dir_keys: &Path,
        config: &'a Config, peer: PeerWithConfig<'a>,
        neighbors: &'a PeerList, parent: Option<PeerWithConfig<'a>>
    ) -> Result<()> 
    {
        let (peer_name, peer_config) = peer;
        macro_rules! str_non_empty_or_global {
            ($name: ident) => {
                if peer_config.$name.is_empty() {
                    &config.$name
                } else {
                    &peer_config.$name
                }
            };
        }
        let composite = CompositeConfig {
            mask: config.mask,
            iface: str_non_empty_or_global!(iface),
            netdev: NetDevConfig {
                name: str_non_empty_or_global!(netdev),
                key: self.get_key_or_new(dir_keys, peer_name)?.0.clone(),
                peers: {
                    let mut peers = Vec::new();
                    macro_rules! add_peer {
                        ($peer_name: ident, $peer_config: ident, $peer_endpoint: expr) => {
                            peers.push(NetDevPeer {
                                name: $peer_name,
                                allowed: Default::default(),
                                pubkey: self.get_key_or_new(dir_keys, $peer_name)?.1.clone(),
                                endpoint: NetDevPeerEndpointAddress::from_str_with_port_global($peer_endpoint, config.port),
                                psk: if config.psk {
                                    Some(self.get_psk_or_new(dir_keys, peer_name, $peer_name)?.clone())
                                } else {
                                    None
                                },
                                keep: vec_string_contains_str(&peer_config.keep, $peer_name)
                            })
                        };
                    }
                    if let Some((parent_name, parent_config)) = parent {
                        add_peer!(parent_name, parent_config, parent_config.endpoint.get(peer_name, PeerEndpointCharacter::Child))
                    }
                    for (neighbor_name, neighbor_config) in neighbors.iter() {
                        if neighbor_name == peer_name ||
                         ! can_neighbors_direct(peer, (neighbor_name, neighbor_config)) {
                            continue
                        }
                        add_peer!(neighbor_name, neighbor_config, neighbor_config.endpoint.get(peer_name, PeerEndpointCharacter::Neighbor))
                    }
                    for (child_name, child_config) in peer_config.children.iter() {
                        add_peer!(child_name, child_config, child_config.endpoint.get(peer_name, PeerEndpointCharacter::Parent))
                    }
                    peers
                },
            },
            network: NetWorkConfig {
                name: str_non_empty_or_global!(network),
                address: &peer_config.ip,
                routes: Default::default(),
            },
        };
        self.route_targets.push(&peer_config.ip);
        for forward in peer_config.forward.iter() {
            self.route_targets.push(&forward)
        }
        let routes_info = RoutesInfo::try_new(peer, parent, neighbors)?;
        match self.map.insert(
            &peer_name, (composite, routes_info)
        ) {
            Some(_) => {
                eprintln!("Duplicated peer {}, please check your config", peer_name);
                Err(Error::ImpossibleLogic)
            },
            None => Ok(()),
        }
    }

    fn try_add_peers(&mut self, 
        dir_keys: &Path, config: &'a Config, peers: &'a PeerList,
        parent: Option<PeerWithConfig<'a>>
    ) -> Result<()> 
    {
        for (peer_name, peer_config) in peers.iter() {
            let peer = (peer_name.as_str(), peer_config);
            self.try_add_peer(dir_keys, config, peer, peers, parent)?;
            self.try_add_peers(dir_keys, config, &peer_config.children, 
                Some((peer_name, peer_config)))?;
        }
        Ok(())
    }

    fn finish_routes(&mut self) -> Result<()> {
        self.route_targets.sort_unstable();
        let routes_count = self.route_targets.len();
        self.route_targets.dedup();
        if routes_count != self.route_targets.len() {
            eprintln!("Duplicate route target, please check your config to make sure all IPs, forwards are unique!");
            return Err(Error::DuplicatedRoute)
        }
        loop {
            let mut new_routes_infos = HashMap::<&str, RoutesMap>::new();
            for (peer_name, (_, routes_info)) in self.map.iter() {
                if routes_info.routes.len() == self.route_targets.len() {
                    continue
                }
                let mut new_routes_info = RoutesMap::new();
                for route_target in self.route_targets.iter() {
                    if routes_info.routes.contains_key(route_target) {
                        continue
                    }
                    // Look for route
                    let mut new_route_info: Option<RouteInfo> = None;
                    for (via, first_jump) in routes_info.nexts.iter() {
                        if via.is_empty() {
                            continue
                        }
                        let peer_routes_info = match self.map.get(via) {
                            Some((_, routes_info)) => routes_info,
                            None => continue,
                        };
                        if let Some(route_info) = peer_routes_info.routes.get(route_target) {
                            let jump = route_info.jump + first_jump;
                            match &new_route_info {
                                Some(new_route_info_inner) => {
                                    if new_route_info_inner.jump > jump {
                                        new_route_info = Some(RouteInfo {
                                            via,
                                            jump,
                                            internal: route_info.internal,
                                        })
                                    }
                                },
                                None => new_route_info = Some(RouteInfo {
                                    via,
                                    jump,
                                    internal: route_info.internal,
                                }),
                            }
                        }
                    }
                    if let Some(new_route_info) = new_route_info {
                        if new_routes_info.insert(route_target, new_route_info).is_some() {
                            eprintln!("Duplicated route for target '{}'", route_target);
                            return Err(Error::DuplicatedRoute)
                        }
                    }
                }
                if ! new_routes_info.is_empty() {
                    if new_routes_infos.insert(peer_name, new_routes_info).is_some() {
                        eprintln!("Duplicated route for peer '{}'", peer_name);
                        return Err(Error::DuplicatedRoute)
                    }
                }
            }
            if new_routes_infos.is_empty() {
                break
            }
            for (update_peer_name, new_routes) in new_routes_infos.iter_mut() {
                match self.map.get_mut(update_peer_name) {
                    Some((_, routes_map)) => routes_map.routes.append(new_routes),
                    None => {
                        eprintln!("Could not find peer {} to update route, impossible", update_peer_name);
                        return Err(Error::ImpossibleLogic)
                    },
                }
            }
        }
        for (_peer_name, (composite_config, routes_info)) in 
            self.map.iter_mut() 
        {
            // let mut peers_map = HashMap::new();
            for (route_target, route_info) in routes_info.routes.iter() {
                if route_info.jump > 1 {
                    if ! route_info.internal {
                        composite_config.network.routes.push(route_target)
                    }
                    for netdev_peer in composite_config.netdev.peers.iter_mut() {
                        if netdev_peer.name == route_info.via {
                            netdev_peer.allowed.push(route_target);
                            break
                        }
                    }
                }
                // println!("{} to {} via {} jump {}", peer_name, route_target, route_info.via, route_info.jump)
            }
        }
        Ok(())
    }

    fn try_write_flattened<P: AsRef<Path>>(&self, dir_all: P) -> Result<()> {
        let flattened = ConfigToSerialize::from(self);
        let path_flattened = dir_all.as_ref().join("config.flattened.yaml");
        let file_flattened = file_create_checked(&path_flattened)?;
        serde_yaml::to_writer(file_flattened, &flattened)?;
        Ok(())
    }

    fn try_from_config<P: AsRef<Path>>(config: &'a Config, dir_all: P) 
        -> Result<Self> 
    {
        let mut result = Self::default();
        let dir_keys = dir_all.as_ref().join("keys");
        create_dir_all_checked(&dir_keys)?;
        result.try_add_peers(&dir_keys, config, &config.peers, None)?;
        result.finish_routes()?;
        result.try_write_flattened(dir_all)?;
        Ok(result)
    }
}

struct WriterBuffer {
    buffer: String,
    tar: tar::Builder<File>,
    mtime: u64,
    dir_config: PathBuf,
    dir_keys: PathBuf,
}

impl WriterBuffer {
    fn new(dir_configs: &Path, name: &str, mtime: u64) -> Result<Self> {
        let dir_config = dir_configs.join(name);
        let dir_keys = dir_config.join("keys/wg");
        create_dir_all_checked(&dir_keys)?;
        let path_tar = dir_configs.join(format!("{}.tar", name));
        let file_tar = file_create_checked(&path_tar)?;
        let tar = tar::Builder::new(file_tar);
        let mut buffer = Self {
            buffer: String::new(),
            tar,
            mtime,
            dir_config,
            dir_keys,
        };
        let mut header = buffer.new_tar_header_directory_keys()?;
        buffer.tar.append_data(&mut header, "keys", std::io::empty())?;
        buffer.tar.append_data(&mut header, "keys/wg", std::io::empty())?;
        Ok(buffer)
    }

    fn new_tar_header(&self, group: &str, mode: u32, folder: bool, size: usize) -> Result<tar::Header> {
        let mut header = tar::Header::new_gnu();
        header.set_username("root")?;
        header.set_groupname(group)?;
        header.set_mode(mode);
        header.set_mtime(self.mtime);
        header.set_size(size as u64);
        if folder {
            header.set_entry_type(tar::EntryType::Directory);
        }
        Ok(header)
    }

    fn new_tar_header_directory(&self, group: &str, mode: u32) -> Result<tar::Header> {
        self.new_tar_header(group, mode, true, 0)
    }

    fn new_tar_header_directory_keys(&self) -> Result<tar::Header> {
        self.new_tar_header_directory("systemd-network", 0o750)
    }

    fn new_tar_header_file(&self, group: &str, mode: u32, size: usize) -> Result<tar::Header> {
        self.new_tar_header(group, mode, false, size)
    }

    fn new_tar_header_file_key(&self) -> Result<tar::Header> {
        self.new_tar_header_file("systemd-network", 0o640, WireGuardKey::LEN_BASE64)
    }

    fn new_tar_header_file_config(&self, size: usize) -> Result<tar::Header> {
        self.new_tar_header_file("root", 0o644, size)
    }

    fn add_key_file(&mut self, key_file: &NetDevKeyFile) -> Result<()> {
        self.buffer.push_str(&key_file.name);
        let key_base64 = key_file.base64()?;
        content_to_file(&key_base64, self.dir_keys.join(&key_file.name))?;
        let mut header = self.new_tar_header_file_key()?;
        self.tar.append_data(&mut header, format!("keys/wg/{}", &key_file.name), key_base64.as_slice())?;
        Ok(())
    }

    fn finish_config(&mut self, name: &str) -> Result<()> {
        let bytes = self.buffer.as_bytes();
        content_to_file(bytes, 
            self.dir_config.join(name))?;
        let mut header = self.new_tar_header_file_config(bytes.len())?;
        self.tar.append_data(&mut header, name, bytes)?;
        Ok(())
    }

    fn finish_tar(&mut self) -> Result<()> {
        self.tar.finish()?;
        Ok(())
    }

    fn push_str(&mut self, str: &str) {
        self.buffer.push_str(str)
    }

    fn push(&mut self, char: char) {
        self.buffer.push(char)
    }

    fn push_endpoint(&mut self, endpoint: &NetDevPeerEndpointAddress) -> Result<()> {
        endpoint.push_to_string(&mut self.buffer)
    }

    fn clear(&mut self) {
        self.buffer.clear()
    }
}

impl<'a> ConfigsToWrite<'a> {
    fn try_from_config<P: AsRef<Path>>(config: &'a Config, dir_all: P) 
        -> Result<Self> 
    {
        let configs_parsing = 
            ConfigsToWriteParsing::try_from_config(config, dir_all)?;
        let map = 
            configs_parsing.map.into_iter().map(
                |(name, config)|
                    (name, config.0)).collect();
        Ok(Self { map })
    }

    fn try_write<P: AsRef<Path>>(&self, dir_all: P) -> Result<()> {
        let dir_configs = dir_all.as_ref().join("configs");
        let _ = remove_dir_all(&dir_configs);
        create_dir_all_checked(&dir_configs)?;
        // create_dir_all_checked(dir_keys)?;
        let mtime = match std::time::SystemTime::now().duration_since(std::time::SystemTime::UNIX_EPOCH) {
            Ok(mtime) => mtime.as_secs(),
            Err(e) => {
                eprintln!("Current time earlier than UNIX Epoch: {}, impossible", e);
                return Err(Error::ImpossibleLogic)
            },
        };
        for (name, config) in self.map.iter() {
            let mut buffer = WriterBuffer::new(&dir_configs, name, mtime)?;
            let netdev = &config.netdev;
            buffer.push_str("[NetDev]\nName=");
            buffer.push_str(&config.iface);
            buffer.push_str("\n\
                Kind=wireguard\n\n\
                [WireGuard]\n\
                ListenPort=51820\n\
                PrivateKeyFile=/etc/systemd/network/keys/wg/");
            buffer.add_key_file(&netdev.key)?;
            buffer.push('\n');
            for peer in netdev.peers.iter() {
                buffer.push_str("\n# ");
                buffer.push_str(&peer.name);
                buffer.push_str("\n[WireGuardPeer]\nPublicKey=");
                buffer.push_str(&peer.pubkey.base64_string());
                if let Some(psk) = &peer.psk {
                    buffer.push_str("\nPresharedKeyFile=/etc/systemd/network/keys/wg/");
                    buffer.add_key_file(psk)?;
                }
                if ! peer.endpoint.is_empty() {
                    buffer.push_str("\nEndpoint=");
                    buffer.push_endpoint(&peer.endpoint)?
                }
                for allowed in peer.allowed.iter() {
                    buffer.push_str("\nAllowedIPs=");
                    buffer.push_str(&allowed);
                }
                if peer.keep {
                    buffer.push_str("\nPersistentKeepalive=25");
                }
                buffer.push('\n');
            }
            buffer.finish_config(&format!("{}.netdev", netdev.name))?;
            buffer.clear();
            
            let network = &config.network;
            buffer.clear();
            buffer.push_str("[Match]\nName=");
            buffer.push_str(&config.iface);
            buffer.push_str("\n\n[Network]\nAddress=");
            buffer.push_str(&network.address);
            buffer.push('/');
            buffer.push_str(&format!("{}", &config.mask));
            for route in network.routes.iter() {
                buffer.push_str("\n\n[Route]\nDestination=");
                buffer.push_str(route);
                if ! route.contains(":") {
                    buffer.push_str("\nScope=link")
                }
            }
            buffer.push('\n');
            buffer.finish_config(&format!("{}.network", network.name))?;
            buffer.finish_tar()?;
        }
        Ok(())
    }
}

type PeerListToSerialize<'a> = BTreeMap<&'a str, PeerConfigToSerialize<'a>>;

#[derive(Debug, Serialize)]
/// Config of a peer
struct PeerConfigToSerialize<'a> {
    ip: &'a str,
    #[serde(default)]
    netdev: &'a str,
    #[serde(default)]
    network: &'a str,
    #[serde(default)]
    iface: &'a str,
    #[serde(default)]
    endpoint: HashMap<&'a str, &'a str>,
    #[serde(default)]
    forward: Vec<&'a str>,
    direct: Option<Vec<&'a str>>,
    #[serde(default)]
    keep: Vec<&'a str>,
}

#[derive(Debug, Serialize)]
struct ConfigToSerialize<'a> {
    #[serde(default = "default_psk")]
    psk: bool,
    netdev: &'a str,
    network: &'a str,
    #[serde(default = "default_mask")]
    mask: u8,
    #[serde(default = "default_iface")]
    iface: &'a str,
    #[serde(default = "default_port")]
    port: u16,
    peers: PeerListToSerialize<'a>,
}

impl<'a> From<&'a ConfigsToWriteParsing<'a>> for ConfigToSerialize<'a> {
    fn from(value: &'a ConfigsToWriteParsing<'a>) -> Self {
        let peers = value.map.iter().map(|(peer_name, (composite, routes_info))| {
            let netdev = &composite.netdev;
            let network = &composite.network;
            let mut keep = Vec::new();
            let mut direct = Vec::new();
            for netdev_peer in netdev.peers.iter() {
                direct.push(netdev_peer.name);
                if netdev_peer.keep {
                    keep.push(netdev_peer.name)
                }
            }
            let mut forward = Vec::new();
            for (route_target, route_info) in routes_info.routes.iter() {
                if ! route_info.internal {
                    forward.push(*route_target)
                }
            }
            let mut endpoint = HashMap::new();
            for (other_peer_name, (other_composite, _)) in value.map.iter() {
                if other_peer_name == peer_name {
                    continue
                }
                for other_peer in other_composite.netdev.peers.iter() {
                    if other_peer.name == *peer_name {
                        endpoint.insert(*other_peer_name, other_peer.endpoint.raw);
                        break
                    }
                }
            }
            (*peer_name, PeerConfigToSerialize {
                ip: network.address.into(),
                netdev: netdev.name.into(),
                network: network.name.into(),
                iface: composite.iface.into(),
                endpoint,
                forward,
                direct: Some(direct),
                keep
            })
        }).collect();
        Self {
            psk: default_psk(),
            netdev: Default::default(),
            network: Default::default(),
            mask: default_mask(),
            iface: default_iface_borrowed(),
            port: default_port(),
            peers,
        }
    }
}

fn main() -> Result<()> { // arg1: config file, arg2: output dir
    let mut args = std::env::args_os();
    let config = args.nth(1).ok_or(Error::ArgumentNotRight)?;
    let output = args.next().ok_or(Error::ArgumentNotRight)?;
    let mut file = file_open_checked(&config)?;
    let config: Config = yaml_from_reader_checked(&mut file)?;
    let configs_to_write = 
        ConfigsToWrite::try_from_config(&config, &output)?;
    configs_to_write.try_write(&output)
}
