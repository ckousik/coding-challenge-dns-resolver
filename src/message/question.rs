use crate::errors::DnsError;

use super::label::{self, Label};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub qname: Vec<Label>,
    pub qtype: u16,
    pub qclass: u16,
}

impl Question {
    pub fn parse(b: &[u8]) -> Result<(usize, Self), DnsError> {
        let (read, labels) = label::parse_label_bytes(b)?;
        if b.len() <= read + 3 {
            return Err(DnsError::ParseError(format!(
                "parse: require {} bytes for parsing question, found {}",
                read + 3,
                b.len(),
            )));
        }

        let qtype_b = [b[read], b[read + 1]];
        let qclass_b = [b[read + 2], b[read + 3]];
        let q = Question {
            qname: labels,
            qtype: u16::from_be_bytes(qtype_b),
            qclass: u16::from_be_bytes(qclass_b),
        };
        return Ok((read + 4, q));
    }

    pub fn write(&self, dest: &mut [u8]) -> Result<usize, DnsError> {
        let written = label::write_labels(&self.qname, dest)?;
        if dest.len() <= written + 3 {
            return Err(DnsError::MarshalError(format!(
                "write: require {} bytes for writing question, found {}",
                written + 3,
                dest.len(),
            )));
        }
        let qtype_b = self.qtype.to_be_bytes();
        let qclass_b = self.qclass.to_be_bytes();
        dest[written] = qtype_b[0];
        dest[written + 1] = qtype_b[1];
        dest[written + 2] = qclass_b[0];
        dest[written + 3] = qclass_b[1];

        Ok(written + 4)
    }
}
