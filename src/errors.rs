use std::error::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsError {
    Generic(String),
    ParseError(String),
    MarshalError(String),
}

impl std::fmt::Display for DnsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Error for DnsError {}
