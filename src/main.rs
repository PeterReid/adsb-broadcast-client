extern crate crypto;
extern crate rand;

mod packet;

use crypto::ed25519;
use std::net::SocketAddr;
use crate::packet::Packet;
use crate::packet::PacketUID;
use crate::packet::Body;
use std::collections::HashMap;
use std::net::UdpSocket;
use std::mem::swap;
use std::time::Duration;
use std::net::ToSocketAddrs;
use std::time::SystemTime;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use rand::Rng;
use std::thread::sleep;
use std::io::ErrorKind;

type PublicKey = [u8; 32];
type PrivateKey = [u8; 64];

#[derive(Debug)]
enum HandleError {
    Malformed,
    Duplicate,
    IrrelevantTime,
    InvalidSignature,
}

struct Client {
    root_hostname: String,
    root_addr: Option<SocketAddr>,
    root_public_key: PublicKey,
    
    private_key: PrivateKey,
    public_key: PublicKey,
    
    echo_to: Vec<SocketAddr>,
    received_packet_count: HashMap<SocketAddr, usize>,
    
    
    very_recently_received: HashMap<PacketUID, Vec<SocketAddr>>,
    semi_recently_received: HashMap<PacketUID, Vec<SocketAddr>>,
    
    irrelevance_millis_since_epoch: u64,
    
    socket: Option<UdpSocket>,
}

enum Uniqueness {
    AlreadyReceivedFromElsewhere,
    AlreadyReceivedFromThere,
    Unique,
}

impl Client {
    fn count_packet_received(&mut self, _packet: &Packet, source: &SocketAddr) {
        *self.received_packet_count.entry(*source).or_insert(0) += 1;
    }
    
    fn check_time_relevance(&self, packet: &Packet) -> bool {
        self.irrelevance_millis_since_epoch < packet.milliseconds_since_epoch
    }
    
    fn discard_old_messages(&mut self) {
        match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
            Ok(since_epoch) => {
                let millis_since_epoch = since_epoch.as_millis() as u64;
                if millis_since_epoch > self.irrelevance_millis_since_epoch + 120*1000 {
                    self.irrelevance_millis_since_epoch = millis_since_epoch - 60*1000;
                    swap(&mut self.semi_recently_received, &mut self.very_recently_received);
                    self.very_recently_received.clear();
                }
            }
            Err(_) => {},
        }
    }
    
    fn consume_uniqueness(&mut self, packet: &Packet, source: &SocketAddr) -> Uniqueness {
        self.discard_old_messages();
    
        let very_recent = self.very_recently_received.entry(packet.uid).or_insert(Vec::new());
        
        if very_recent.contains(source) {
            return Uniqueness::AlreadyReceivedFromThere;
        }
        
        let unique_very_recently = very_recent.is_empty();
        very_recent.push(*source);
        
        if let Some(semi_recent) = self.semi_recently_received.get(&packet.uid) {
            if semi_recent.contains(source) {
                return Uniqueness::AlreadyReceivedFromThere;
            } else {
                return Uniqueness::AlreadyReceivedFromElsewhere;
            }
        }
        
        if unique_very_recently {
            Uniqueness::Unique
        } else {
            Uniqueness::AlreadyReceivedFromElsewhere
        }
    }
    
    fn check_signature(&self, signature: &[u8], signed: &[u8]) -> bool {
        ed25519::verify(signed, &self.root_public_key, signature)
    }
    
    fn handle_packet(&mut self, source: &SocketAddr, data: &[u8]) -> Result<(), HandleError> {
        let packet = Packet::parse(data).ok_or(HandleError::Malformed)?;
        
        if !self.check_signature(packet.signature, packet.signed) {
            return Err(HandleError::InvalidSignature);
        }
        
        if !self.check_time_relevance(&packet) {
            return Err(HandleError::IrrelevantTime);
        }
        
        match self.consume_uniqueness(&packet, source) {
            Uniqueness::Unique => {
                self.count_packet_received(&packet, source);
            },
            Uniqueness::AlreadyReceivedFromElsewhere => {
                // The sender still gets credit for sending this, even though we 
                self.count_packet_received(&packet, source);
                return Err(HandleError::Duplicate);
            },
            Uniqueness::AlreadyReceivedFromThere => {
                // Same packet received twice from the same source is odd. Something is amiss or they are trying to cheat somehow.
                // In any case, do not give the sender credit for this.
                return Err(HandleError::Duplicate);
            }
        }
        
        match packet.get_body() {
            Some(Body::Payload(payload)) => {
                if let Some(ref socket) = self.socket {
                    for dest in self.echo_to.iter() {
                        if let Err(e) = socket.send_to(data, dest) {
                            eprintln!("Error sending data to {:?}: {:?}", dest, e);
                        }
                    }
                }
                
                for data_elem in payload {
                    println!("Data {:?}", data_elem);
                }
            }
            Some(Body::Configuration(intended_recipient, destinations)) => {
                if intended_recipient == self.public_key {
                    self.echo_to = destinations.collect();
                }
            }
            None => {
                
            }
        }
        Ok( () )
    }
    
    fn new(root_hostname: String, root_public_key: PublicKey, key_seed: &[u8]) -> Client {
        let (secret_key, public_key) = ed25519::keypair(key_seed);

        let irrelevance_millis_since_epoch = 
            match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
                Ok(since_epoch) => {
                    let millis_since_epoch = since_epoch.as_millis() as u64;
                    millis_since_epoch - 60*1000
                }
                Err(_) => 0, // No defense against replays, since we do not know the time.
            };
        
        Client{
            root_hostname: root_hostname,
            root_addr: None,
            root_public_key: root_public_key,
            
            private_key: secret_key,
            public_key: public_key,
            
            echo_to: Vec::new(),
            received_packet_count: HashMap::new(),
            
            
            very_recently_received: HashMap::new(),
            semi_recently_received: HashMap::new(),
            
            irrelevance_millis_since_epoch: irrelevance_millis_since_epoch,
            
            socket: None,
        
        }
    }
    
    fn resolve_host(&mut self) {
        self.socket = None;
        self.root_addr = None;
        
        if let Ok(Some(root_addr)) = self.root_hostname.to_socket_addrs().map(|mut socket_addrs| socket_addrs.next()) {
            // Bind either an IPV4 or IPV6 address, depending on what the root resolved to.
            let bind_to_addr = match root_addr {
                SocketAddr::V4(_) => {
                    IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))
                }
                SocketAddr::V6(_) => {
                    IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0))
                }
            };
            
            let mut rng = rand::thread_rng();
            for _ in 0..20 {
                let port: u16 = 20000 + rng.gen::<u16>() % 10000;
                if let Ok(socket) = UdpSocket::bind((bind_to_addr, port)) {
                    // In case we never receive anything, we still need to report stats to the root sometimes
                    if let Err(e) = socket.set_read_timeout(Some(Duration::from_secs(10))) {
                        eprintln!("Error setting socket timeout: {:?}", e);
                    }
                    self.socket = Some(socket);
                    self.root_addr = Some(root_addr);
                    return;
                }
            }
        }
    
    }
    
    pub fn run(&mut self) {
        loop {
            self.resolve_host();
        
            let mut buf = [0u8; 10000];
            let (packet_len, source) = if let Some(ref socket) = self.socket {
                match socket.recv_from(&mut buf) {
                    Ok(x) => x,
                    Err(e) => {
                        if e.kind() == ErrorKind::TimedOut || e.kind() == ErrorKind::WouldBlock {
                            // This is fine. We time out so we can send the status occasionally and whatnot.
                        } else {
                            eprintln!("Failed to receive from socket: {:?}", e);
                            
                            self.socket = None;
                            self.root_addr = None;
                            sleep(Duration::from_secs(2)); // Avoid a busy loop
                        }
                        continue;
                    }
                }
            } else {
                sleep(Duration::from_secs(2));
                continue;
            };
            
            let packet = &buf[..packet_len];
            
            match self.handle_packet(&source, packet) {
                Ok( () ) => { }
                Err( e ) => {
                    eprintln!("Error handling packet: {:?}", e);
                }
            }
        }
    }
}


fn main() {
    println!("Hello, world!");
    let root_public_key = [
        0,1,2,3,4,5,6,7,8,9,
        0,1,2,3,4,5,6,7,8,9,
        0,1,2,3,4,5,6,7,8,9,
        0,1
    ];
    let mut client = Client::new("localhost:19040".to_string(), root_public_key, &[1,2,3,4,5,6,7][..]);
      
    client.run();
}
