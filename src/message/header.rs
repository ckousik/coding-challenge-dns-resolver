// DNS message header definition
pub const HEADER_LENGTH: usize = 12;

pub use crate::errors::DnsError;

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opcode {
    #[default]
    StandardQuery,
    InverseQuery,
    StatusRequest,
    Reserved(u8),
}

impl From<u8> for Opcode {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::StandardQuery,
            1 => Self::InverseQuery,
            2 => Self::StatusRequest,
            _ => Self::Reserved(value),
        }
    }
}

impl Into<u8> for Opcode {
    fn into(self) -> u8 {
        match self {
            Self::StandardQuery => 0,
            Self::InverseQuery => 1,
            Self::StatusRequest => 2,
            Self::Reserved(v) => v,
        }
    }
}

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseCode {
    #[default]
    NoError,
    FormatError,
    ServerFailure,
    NameError,
    NotImpemented,
    Refused,
    Reserved(u8),
}

impl From<u8> for ResponseCode {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::NoError,
            1 => Self::FormatError,
            2 => Self::ServerFailure,
            3 => Self::NameError,
            4 => Self::NotImpemented,
            5 => Self::Refused,
            _ => Self::Reserved(value),
        }
    }
}

impl Into<u8> for ResponseCode {
    fn into(self) -> u8 {
        match self {
            Self::NoError => 0,
            Self::FormatError => 1,
            Self::ServerFailure => 2,
            Self::NameError => 3,
            Self::NotImpemented => 4,
            Self::Refused => 5,
            Self::Reserved(v) => v,
        }
    }
}

/// The header contains the following fields:
///                                1  1  1  1  1  1
///  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                      ID                       |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                    QDCOUNT                    |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                    ANCOUNT                    |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                    NSCOUNT                    |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                    ARCOUNT                    |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Header {
    pub id: u16,
    pub qr: bool,
    pub opcode: Opcode,
    pub aa: bool,
    pub tc: bool,
    pub rd: bool,
    pub ra: bool,
    pub rcode: ResponseCode,
    pub qdcount: u16,
    pub ancount: u16,
    pub arcount: u16,
    pub nscount: u16,
}

impl Header {
    pub fn write(&self, dest: &mut [u8]) -> Result<(), DnsError> {
        if dest.len() < 12 {
            return Err(DnsError::MarshalError(
                "write: header requires at least 12 bytes".to_string(),
            ));
        }

        // write id
        let id_b = self.id.to_be_bytes();
        dest[0] = id_b[0];
        dest[1] = id_b[1];

        // write qr
        dest[2] = if self.qr { 1 } else { 0 } << 7;

        // write opcode
        let opcode: u8 = self.opcode.into();
        dest[2] |= opcode << 3;

        // write aa
        dest[2] |= if self.aa { 1u8 } else { 0u8 } << 2;

        // write tc
        dest[2] |= if self.tc { 1u8 } else { 0u8 } << 1;

        // write rd
        dest[2] |= if self.rd { 1u8 } else { 0u8 };

        // write ra
        dest[3] = if self.ra { 1u8 } else { 0u8 } << 7;

        // write rcode
        let rcode: u8 = self.rcode.into();
        dest[3] |= rcode;

        // write qdcount
        let b = self.qdcount.to_be_bytes();
        dest[4] = b[0];
        dest[5] = b[1];

        // write ancount
        let b = self.ancount.to_be_bytes();
        dest[6] = b[0];
        dest[7] = b[1];

        // write arcount
        let b = self.arcount.to_be_bytes();
        dest[8] = b[0];
        dest[9] = b[1];

        // write nscount
        let b = self.nscount.to_be_bytes();
        dest[10] = b[0];
        dest[11] = b[1];
        Ok(())
    }

    pub fn parse(src: &[u8]) -> Result<Self, DnsError> {
        if src.len() < 12 {
            return Err(DnsError::ParseError(
                "read: header should have 12 bytes".to_string(),
            ));
        }
        let mut hdr = Self::default();
        hdr.id = u16::from_be_bytes([src[0], src[1]]);
        hdr.qdcount = u16::from_be_bytes([src[4], src[5]]);
        hdr.ancount = u16::from_be_bytes([src[6], src[7]]);
        hdr.arcount = u16::from_be_bytes([src[8], src[9]]);
        hdr.nscount = u16::from_be_bytes([src[10], src[11]]);

        hdr.qr = src[2] & 0x80 != 0;
        hdr.aa = src[2] & 0x04 != 0;
        hdr.tc = src[2] & 0x02 != 0;
        hdr.rd = src[2] & 0x01 != 0;
        hdr.ra = src[3] & 0x80 != 0;

        hdr.opcode = (src[2] & 0x78 >> 3).into();
        hdr.rcode = (src[3] & 0x0f).into();

        Ok(hdr)
    }
}

#[cfg(test)]
mod test {

    use super::{Header, Opcode, ResponseCode, HEADER_LENGTH};

    #[test]
    fn test_write_and_parse_header() {
        let mut initial_header = Header::default();
        initial_header.id = rand::random::<u16>();
        initial_header.qr = true;
        initial_header.tc = true;
        initial_header.ra = true;

        initial_header.qdcount = 5;
        initial_header.ancount = 3;
        initial_header.arcount = 2;
        initial_header.nscount = 7;

        initial_header.opcode = Opcode::StatusRequest;
        initial_header.rcode = ResponseCode::NoError;

        let mut buf = [0u8; HEADER_LENGTH];

        initial_header.write(&mut buf).unwrap();

        let parsed_header = Header::parse(&buf[..]).unwrap();

        assert_eq!(initial_header, parsed_header);
    }
}
