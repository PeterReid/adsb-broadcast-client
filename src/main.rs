mod packet;

use std::net::SocketAddr;
use crate::packet::Packet;
use crate::packet::PacketUID;
use std::collections::HashMap;
use std::net::UdpSocket;
use std::mem::swap;
use std::time::Duration;
use std::time::Instant;

type PublicKey = [u8; 32];
type PrivateKey = [u8; 32];

enum HandleError {
    Malformed,
    Duplicate,
    IrrelevantTime,
    InvalidSignature,
}

struct Client {
    root_hostname: String,
    root_addr: SocketAddr,
    root_public_key: PublicKey,
    
    private_key: PrivateKey,
    public_key: PublicKey,
    
    echo_to: Vec<SocketAddr>,
    received_packet_count: HashMap<SocketAddr, usize>,
    
    
    very_recently_received: HashMap<PacketUID, Vec<SocketAddr>>,
    semi_recently_received: HashMap<PacketUID, Vec<SocketAddr>>,
    
    
    root_time_base: u64,
    local_time_base: Instant,
    irrelevance_threshold: Duration,
    
    socket: UdpSocket,
}

enum Uniqueness {
    AlreadyReceivedFromElsewhere,
    AlreadyReceivedFromThere,
    Unique,
}

impl Client {
    fn count_packet_received(&mut self, packet: &Packet, source: &SocketAddr) {
        *self.received_packet_count.entry(*source).or_insert(0) += 1;
    }
    
    fn check_time_relevance(&self, packet: &Packet) -> bool {
        let since_base = Duration::from_millis(packet.milliseconds_since_epoch.wrapping_sub(self.root_time_base));
        since_base > self.irrelevance_threshold && since_base < self.irrelevance_threshold + Duration::from_secs(60*60)
    }
    
    fn discard_old_messages(&mut self) {
        let now = Instant::now();
        if self.local_time_base + self.irrelevance_threshold + Duration::from_secs(120) < now {
            self.irrelevance_threshold += Duration::from_secs(60);
            
            swap(&mut self.semi_recently_received, &mut self.very_recently_received);
            self.very_recently_received.clear();
        }
    }
    
    fn consume_uniqueness(&mut self, packet: &Packet, source: &SocketAddr) -> Uniqueness {
        self.discard_old_messages();
    
        let very_recent = self.very_recently_received.entry(packet.uid).or_insert(Vec::new());
        
        if very_recent.contains(source) {
            return Uniqueness::AlreadyReceivedFromThere;
        }
        
        let mut unique_very_recently = very_recent.is_empty();
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
    
    fn check_signature(&self, _signature: &[u8], _signed: &[u8]) -> bool {
        true
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
        
        if packet.kind == 1 {
            for dest in self.echo_to.iter() {
                self.socket.send_to(data, dest);
            }
        } else if packet.kind == 2 {
            
        }
        Ok( () )
    }
}


fn main() {
    println!("Hello, world!");
    
    
}
