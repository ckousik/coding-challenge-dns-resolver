use crate::errors::DnsError;
// parsing message labels with compression

/// Label can be of the form:
/// 1. [(length octet (max 63 octets)) (octets)] (0)
/// 2. (Label 1)(offset pointer)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Label {
    L(String),
    P(usize),
}

pub fn parse_label_bytes(b: &[u8]) -> Result<(usize, Vec<Label>), DnsError> {
    let mut result = vec![];
    let mut idx = 0usize;
    let mut reached_end = false;
    while idx < b.len() {
        // check if pointer
        if b[idx] & 0xC0 == 0xC0 {
            let offset_b0 = b[idx] ^ 0xC0;
            idx += 1;

            if idx >= b.len() {
                return Err(DnsError::ParseError(format!(
                    "parse label: require {} bytes for parsing label offset, found {}",
                    idx + 1,
                    b.len()
                )));
            }

            let offset_b1 = b[idx];
            idx += 1;
            let offset = u16::from_be_bytes([offset_b0, offset_b1]);
            result.push(Label::P(offset as usize));
            reached_end = true;
            break;
        }

        // check zero octet
        if b[idx] == 0 {
            idx += 1;
            reached_end = true;
            break;
        }

        // read label
        let count = u8::from_be(b[idx]) as usize;
        // check length
        if idx + count >= b.len() {
            return Err(DnsError::ParseError(format!(
                "parse: require {} bytes for parsing label, found {}, {:?}",
                idx + count + 1,
                b.len(),
                result,
            )));
        }
        result.push(Label::L(
            String::from_utf8_lossy(&b[idx + 1..idx + count + 1]).into_owned(),
        ));
        idx += count + 1;
    }

    if !reached_end {
        return Err(DnsError::ParseError(format!(
            "parse: zero-octet or pointer not found"
        )));
    }
    Ok((idx, result))
}

/// resolves pointers in a label.
const MAX_LABEL_RESOLVE_DEPTH: usize = 10;
pub fn resolve_labels(msg: &[u8], labels: &mut Vec<Label>) -> Result<String, DnsError> {
    let mut iter_count = 0;
    while let Some(label) = labels.pop() {
        if iter_count == MAX_LABEL_RESOLVE_DEPTH {
            return Err(DnsError::ParseError(format!(
                "parse: could not resolve labels after a depth of 10, possible cycle"
            )));
        }
        let offset = match label {
            Label::L(_) => {
                labels.push(label);
                break;
            }
            Label::P(offset) => offset,
        };

        let (_, next) = parse_label_bytes(&msg[offset..])?;
        for label in next {
            labels.push(label)
        }
        iter_count += 1;
    }
    let domain = labels
        .clone()
        .into_iter()
        .filter_map(|l| match l {
            Label::L(s) => Some(s),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join(".");
    Ok(domain)
}

pub fn domain_to_labels(domain: &str) -> Result<Vec<Label>, DnsError> {
    let mut result = vec![];
    for part in domain.split('.') {
        if part.len() > 63 {
            return Err(DnsError::Generic(format!(
                "label cannot have more than 63 octets"
            )));
        }
        result.push(Label::L(part.to_string()))
    }
    Ok(result)
}

pub fn write_labels(labels: &Vec<Label>, dest: &mut [u8]) -> Result<usize, DnsError> {
    if labels.len() == 0 {
        return Ok(0);
    }

    let mut idx = 0;
    let mut wrote_offset = false;
    for label in labels {
        if dest.len() <= idx {
            return Err(DnsError::MarshalError(format!(
                "write: not enough space in destination to write labels"
            )));
        }
        match label {
            Label::L(s) => {
                dest[idx] = s.len() as u8;
                idx += 1;
                for b in s.as_bytes() {
                    if dest.len() <= idx {
                        return Err(DnsError::MarshalError(format!(
                            "write: not enough space in destination to write labels"
                        )));
                    }
                    dest[idx] = *b;
                    idx += 1;
                }
            }
            Label::P(offset) => {
                let offset_b = (*offset as u16).to_be_bytes();
                dest[idx] = 0xC0 | (offset_b[0] as u8);
                idx += 1;
                if dest.len() <= idx {
                    return Err(DnsError::MarshalError(format!(
                        "write: not enough space in destination to write labels"
                    )));
                }
                dest[idx] = offset_b[1];
                idx += 1;
                wrote_offset = true;
                break;
            }
        }
    }

    if !wrote_offset {
        dest[idx] = 0;
        idx += 1;
    }

    Ok(idx)
}

#[cfg(test)]
mod test {

    use super::{parse_label_bytes, resolve_labels, write_labels, Label};

    #[test]
    fn test_simple_parse_label() {
        let b = vec![
            vec![3u8],
            "dns".as_bytes().to_vec(),
            vec![6u8],
            "google".as_bytes().to_vec(),
            vec![3u8],
            "com".as_bytes().to_vec(),
            vec![0u8],
        ]
        .concat();

        let (_, labels) = parse_label_bytes(&b[..]).unwrap();
        assert_eq!(labels.len(), 3);
        assert_eq!(labels[0], Label::L(String::from("dns")));
        assert_eq!(labels[1], Label::L(String::from("google")));
        assert_eq!(labels[2], Label::L(String::from("com")));
    }

    #[test]
    fn test_parse_with_pointer() {
        let b = vec![vec![3u8], "dns".as_bytes().to_vec(), vec![0xC0, 0x0F]].concat();
        let (_, labels) = parse_label_bytes(&b[..]).unwrap();
        assert_eq!(labels.len(), 2);
        assert_eq!(labels[0], Label::L(String::from("dns")));
        assert_eq!(labels[1], Label::P(0x0F as usize));
    }

    #[test]
    fn test_resolve_labels() {
        let b = vec![
            vec![3u8],
            "dns".as_bytes().to_vec(),
            vec![6u8],
            "google".as_bytes().to_vec(),
            vec![3u8],
            "com".as_bytes().to_vec(),
            vec![0u8],
        ]
        .concat();
        let b2 = vec![vec![4u8], "test".as_bytes().to_vec(), vec![0xC0, 0x04]].concat();

        let (_, mut labels) = parse_label_bytes(b2.as_slice()).unwrap();

        resolve_labels(b.as_slice(), &mut labels).unwrap();

        assert_eq!(labels.len(), 3);
        assert_eq!(labels[0], Label::L(String::from("test")));
        assert_eq!(labels[1], Label::L(String::from("google")));
        assert_eq!(labels[2], Label::L(String::from("com")));
    }

    #[test]
    fn test_resolve_cycle() {
        let b = vec![
            vec![3u8],
            "dns".as_bytes().to_vec(),
            vec![6u8],
            "google".as_bytes().to_vec(),
            vec![0xC0, 0x00],
        ]
        .concat();
        let (_, mut labels) = parse_label_bytes(b.as_slice()).unwrap();
        assert_eq!(labels.len(), 3);
        assert_eq!(labels[2], Label::P(0));

        resolve_labels(b.as_slice(), &mut labels).unwrap_err();
    }

    #[test]
    fn test_write_and_parse_labels() {
        let b = vec![
            vec![3u8],
            "dns".as_bytes().to_vec(),
            vec![6u8],
            "google".as_bytes().to_vec(),
            vec![3u8],
            "com".as_bytes().to_vec(),
            vec![0u8],
        ]
        .concat();

        let (_, labels) = parse_label_bytes(&b[..]).unwrap();
        assert_eq!(labels.len(), 3);
        assert_eq!(labels[0], Label::L(String::from("dns")));
        assert_eq!(labels[1], Label::L(String::from("google")));
        assert_eq!(labels[2], Label::L(String::from("com")));

        let mut d = vec![0u8; 100];
        let n = write_labels(&labels, d.as_mut_slice()).unwrap();
        assert_eq!(b.len(), n);
        assert_eq!(b.as_slice(), &d[..n]);
    }

    #[test]
    fn test_write_and_parse_labels_with_offset() {
        let b = vec![vec![3u8], "dns".as_bytes().to_vec(), vec![0xC0, 0x0F]].concat();
        let (_, labels) = parse_label_bytes(&b[..]).unwrap();
        assert_eq!(labels.len(), 2);
        assert_eq!(labels[0], Label::L(String::from("dns")));
        assert_eq!(labels[1], Label::P(0x0F as usize));

        let mut dest = vec![0u8; 100];
        let n = write_labels(&labels, dest.as_mut_slice()).unwrap();
        assert_eq!(b.len(), n);
        assert_eq!(b.as_slice(), &dest[..n]);
    }
}
