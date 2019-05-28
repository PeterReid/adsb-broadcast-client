use std::net::SocketAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::IpAddr;

/// Probably unique in some small stretch of time. Not globally unique, but that would usually be overkill.
pub type PacketUID = u64;

pub struct Packet<'a> {
    pub signature: &'a [u8],
    pub uid: PacketUID,
    pub signed: &'a [u8],
    pub milliseconds_since_epoch: u64,
    pub kind: u8,
    pub body: &'a [u8],
}

struct DestinationIterator<'a> {
    body: &'a [u8]
}
impl <'a> Iterator for DestinationIterator<'a> {
    type Item = SocketAddr;
    
    fn next(&mut self) -> Option<SocketAddr> {
        let kind = if let Some(kind) = self.body.get(0) {
            *kind
        } else {
            return None;
        };
        
        if kind == 4 {
            if self.body.len() < 1 + 4 + 2{
                return None;
            }
            
            let ret = Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(self.body[1], self.body[2], self.body[3], self.body[4])), 
                u16::from_le_bytes([self.body[5], self.body[6]])
            ));
            self.body = self.body.split_at(1 + 4 + 2).1;
            
            ret
        } else if kind == 6 {
            if self.body.len() < 1 + 16 + 2 {
                return None;
            }
            let ret = Some(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(
                    u16::from_le_bytes([self.body[1], self.body[2]]),
                    u16::from_le_bytes([self.body[3], self.body[4]]),
                    u16::from_le_bytes([self.body[5], self.body[6]]),
                    u16::from_le_bytes([self.body[7], self.body[8]]),
                    u16::from_le_bytes([self.body[9], self.body[10]]),
                    u16::from_le_bytes([self.body[11], self.body[12]]),
                    u16::from_le_bytes([self.body[13], self.body[14]]),
                    u16::from_le_bytes([self.body[15], self.body[16]])
                )),
                u16::from_le_bytes([self.body[17], self.body[18]]) 
            ));
                
            self.body = self.body.split_at(1 + 16 + 2).1;
            ret
        } else {
            return None;
        }
    }
}

impl<'a> Packet<'a> {
    pub fn parse(data: &'a [u8]) -> Option<Packet<'a>> {
        if data.len() < 32 + 8 + 1 {
            return None;
        }
        
        let signature = &data[0..32];
        let signed = &data[32..];
        
        let mut milliseconds_since_epoch_bytes = [0u8; 8];
        milliseconds_since_epoch_bytes.copy_from_slice(&data[32..40]);
        
        let mut uid_bytes = [0u8; 8];
        uid_bytes.copy_from_slice(&signature[0..8]);
        
        let kind = data[40];
        let body = &data[41..];
        
        Some(Packet {
            signature: signature,
            signed: signed,
            uid: u64::from_le_bytes(uid_bytes),
            milliseconds_since_epoch: u64::from_le_bytes(milliseconds_since_epoch_bytes),
            kind: kind,
            body: body,
        })
        
    }
    
    
}

