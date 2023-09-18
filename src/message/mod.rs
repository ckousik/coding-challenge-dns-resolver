// message definitions

use self::{
    header::{DnsError, HEADER_LENGTH},
    label::{domain_to_labels, resolve_labels},
};

pub mod header;
pub mod label;
pub mod question;
pub mod rr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub hdr: header::Header,
    pub qd: Vec<question::Question>,
    pub an: Vec<rr::ResourceRecord>,
    pub ar: Vec<rr::ResourceRecord>,
    pub ns: Vec<rr::ResourceRecord>,
}

impl Message {
    pub fn parse(b: &[u8]) -> Result<(usize, Self), DnsError> {
        let mut offset = 0;
        let mut qd = vec![];
        let mut an = vec![];
        let mut ar = vec![];
        let mut ns = vec![];
        let hdr = header::Header::parse(b)?;
        offset += header::HEADER_LENGTH;

        for _ in 0..hdr.qdcount {
            let (read, q) = question::Question::parse(&b[offset..])?;
            offset += read;
            qd.push(q);
        }

        for _ in 0..hdr.ancount {
            let (read, r) = rr::ResourceRecord::parse(&b[offset..])?;
            offset += read;
            an.push(r);
        }

        for _ in 0..hdr.arcount {
            let (read, r) = rr::ResourceRecord::parse(&b[offset..])?;
            offset += read;
            ar.push(r);
        }

        for _ in 0..hdr.nscount {
            let (read, r) = rr::ResourceRecord::parse(&b[offset..])?;
            offset += read;
            ns.push(r);
        }

        for q in &mut qd {
            resolve_labels(b, &mut q.qname)?;
        }

        for r in &mut an {
            resolve_labels(b, &mut r.name)?;
        }

        for r in &mut ar {
            resolve_labels(b, &mut r.name)?;
        }

        for r in &mut ns {
            resolve_labels(b, &mut r.name)?;
        }

        let message = Message {
            hdr,
            qd,
            an,
            ar,
            ns,
        };
        Ok((offset, message))
    }

    pub fn write(&self, dest: &mut [u8]) -> Result<usize, DnsError> {
        let mut offset = 0;
        self.hdr.write(&mut dest[offset..])?;
        offset += HEADER_LENGTH;

        for q in &self.qd {
            let w = q.write(&mut dest[offset..])?;
            offset += w;
        }

        Ok(offset)
    }

    pub fn new_query(domain: &str, t: u16, class: u16, recursion: bool) -> Result<Self, DnsError> {
        let mut hdr = header::Header::default();
        hdr.id = rand::random();
        hdr.qr = false;
        hdr.qdcount = 1;
        hdr.rd = recursion;
        hdr.opcode = header::Opcode::StandardQuery;

        let qname = domain_to_labels(domain)?;

        Ok(Message {
            hdr: hdr,
            qd: vec![question::Question {
                qname: qname,
                qtype: t,
                qclass: class,
            }],
            an: vec![],
            ar: vec![],
            ns: vec![],
        })
    }
}
