use std::{
    env,
    net::{Ipv4Addr, SocketAddrV4, UdpSocket},
    time,
};

use crate::message::label::{parse_label_bytes, resolve_labels};

mod errors;
mod message;

fn main() -> std::io::Result<()> {
    {
        let args: Vec<String> = env::args().collect();
        let mut domain = "dns.google.com";
        if args.len() == 2 {
            domain = &args[1];
        }

        let socket = UdpSocket::bind("0.0.0.0:0")?;
        let well_known: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(198, 41, 0, 4), 53);
        let result = resolve_dns(0, domain, &socket, well_known);
        if let Some(result) = result {
            println!("Found {}", result);
        } else {
            println!("Not found");
        }
    }
    Ok(())
}

fn do_query(
    domain: &str,
    socket: &std::net::UdpSocket,
    saddr: SocketAddrV4,
) -> std::io::Result<(message::Message, [u8; 1600])> {
    println!("Querying {} for {}", saddr, domain);

    let query_msg = message::Message::new_query(domain, 1, 1, false).unwrap();
    let mut qb = [0u8; 1600];
    let mut rb = [0u8; 1600];

    let w = query_msg.write(&mut qb[..]).unwrap();
    let qb = &qb[..w];

    socket.set_read_timeout(Some(time::Duration::from_secs(5)))?;

    socket.send_to(&qb, saddr)?;
    let r = socket.recv(&mut rb[..])?;
    let (_, msg) = message::Message::parse(&rb[..r]).unwrap();
    return Ok((msg, rb));
}

fn resolve_dns_inner(
    depth: usize,
    domain: &str,
    socket: &std::net::UdpSocket,
    saddr: SocketAddrV4,
    ns_map: &mut std::collections::HashMap<String, Ipv4Addr>,
) -> Option<Ipv4Addr> {
    if depth > 3 {
        return None;
    }

    let well_known: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(198, 41, 0, 4), 53);
    let (msg, raw) = do_query(domain, &socket, saddr).unwrap();
    if msg.hdr.rcode != message::header::ResponseCode::NoError {
        println!("Error when querying {}: {:?}", saddr, msg.hdr.rcode);
        return None;
    }
    if msg.hdr.ancount > 0 {
        println!("Found answer for domain: {}", domain);
        for answer in &msg.an {
            // TODO: Handle AAAA records
            if answer.t != 1 {
                continue;
            }
            let rdata = &answer.rdata;
            let addr = std::net::Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]);
            return Some(addr);
        }
    }

    for ns in &msg.ns {
        if ns.t == 1 && ns.class == 1 {
            let mut name = ns.name.clone();
            let domain = resolve_labels(&raw[..], &mut name).unwrap();
            let rdata = &ns.rdata;
            let addr = std::net::Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]);

            ns_map.insert(domain, addr);
        }
    }

    for ar in &msg.ar {
        if ar.t == 2 {
            let rdata = &ar.rdata;
            let (_, mut labels) = parse_label_bytes(rdata.as_slice()).unwrap();
            let ar_domain = resolve_labels(&raw[..], &mut labels).unwrap();
            if domain != ar_domain {
                let addr = ns_map.get(&ar_domain);

                // resolve_dns(depth + 1, &ar_domain, &socket, well_known);
                if let Some(addr) = addr {
                    if let Some(result) = resolve_dns_inner(
                        depth + 1,
                        domain,
                        socket,
                        SocketAddrV4::new(*addr, 53),
                        ns_map,
                    ) {
                        return Some(result);
                    }
                }

                if let Some(addr) =
                    resolve_dns_inner(depth + 1, &ar_domain, socket, well_known, ns_map)
                {
                    if let Some(result) = resolve_dns_inner(
                        depth + 1,
                        domain,
                        socket,
                        SocketAddrV4::new(addr, 53),
                        ns_map,
                    ) {
                        return Some(result);
                    }
                }
            }
        }
    }
    return None;
}

fn resolve_dns(
    depth: usize,
    domain: &str,
    socket: &std::net::UdpSocket,
    saddr: SocketAddrV4,
) -> Option<Ipv4Addr> {
    let mut ns_map = std::collections::HashMap::new();
    return resolve_dns_inner(depth, domain, socket, saddr, &mut ns_map);
}
