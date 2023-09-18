use crate::errors::DnsError;

use super::label::{parse_label_bytes, Label};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ResourceRecord {
    pub name: Vec<Label>,
    pub t: u16,
    pub class: u16,
    pub ttl: u32,
    pub rdlength: u16,
    pub rdata: Vec<u8>,
}

impl ResourceRecord {
    pub fn parse(b: &[u8]) -> Result<(usize, Self), DnsError> {
        let (offset, name) = parse_label_bytes(b)?;
        if offset + 9 >= b.len() {
            return Err(DnsError::ParseError(format!(
                "parse: not enough bytes to parse resource record"
            )));
        }
        let t = u16::from_be_bytes([b[offset], b[offset + 1]]);
        let class = u16::from_be_bytes([b[offset + 2], b[offset + 3]]);
        let ttl = u32::from_be_bytes([b[offset + 4], b[offset + 5], b[offset + 6], b[offset + 7]]);
        let rdlength = u16::from_be_bytes([b[offset + 8], b[offset + 9]]);
        if b.len() < offset + 9 + rdlength as usize {
            return Err(DnsError::ParseError(format!(
                "parse: not enough bytes to parse resource record"
            )));
        }
        if rdlength == 0 {
            return Ok((
                offset + 9 + 1,
                ResourceRecord {
                    name: name,
                    t: t,
                    class: class,
                    ttl: ttl,
                    rdlength: rdlength,
                    rdata: vec![],
                },
            ));
        }
        let rdata = b[offset + 10..offset + 10 + rdlength as usize].to_owned();
        return Ok((
            offset + 9 + rdlength as usize + 1,
            ResourceRecord {
                name: name,
                t: t,
                class: class,
                ttl: ttl,
                rdlength: rdlength,
                rdata: rdata,
            },
        ));
    }
}
