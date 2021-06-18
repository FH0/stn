use super::{
    parse::{Route, RouteAddr},
    Out,
};
use crate::misc::split_addr_str;
use lazy_static::lazy_static;
use log::*;
use parking_lot::RwLock;
use std::{net::IpAddr, sync::Arc};
use trust_dns_proto::op::Message;

lazy_static! {
    pub(crate) static ref OUT: RwLock<Vec<Arc<dyn Out + Send + Sync>>> = RwLock::new(Vec::new());
    pub(crate) static ref ROUTE: RwLock<Vec<Route>> = RwLock::new(Vec::new());
}

pub(crate) fn find_out(
    tag: String,
    network: String,
    saddr: String,
    daddr: String,
    udp_buf: &[u8],
) -> Arc<dyn Out + Send + Sync> {
    for route_iter in &*ROUTE.read() {
        if route_iter.tag.len() != 0 && !route_iter.tag.contains(&tag) {
            continue;
        }

        if route_iter.network.len() != 0 && !route_iter.network.contains(&network) {
            continue;
        }

        match split_addr_str(saddr.as_str()) {
            Ok((saddr, sport)) => {
                if !match_route_addr(&route_iter.saddr, &saddr) {
                    continue;
                }

                if route_iter.sport.len() != 0 && !route_iter.sport.contains(&sport) {
                    continue;
                }
            }
            Err(e) => {
                warn!("split_addr_str {} -> {} {}", saddr, daddr, e);
            }
        }

        match split_addr_str(daddr.as_str()) {
            Ok((daddr, dport)) => {
                if !match_route_addr(&route_iter.daddr, &daddr) {
                    continue;
                }

                if route_iter.dport.len() != 0 && !route_iter.dport.contains(&dport) {
                    continue;
                }
            }
            Err(e) => {
                warn!("split_addr_str {} -> {} {}", saddr, daddr, e);
            }
        }

        // dns_domain
        if network.as_str() == "udp" {
            if let Ok(dns_msg) = Message::from_vec(udp_buf) {
                if dns_msg.queries().len() > 0
                    && !dns_msg
                        .queries()
                        .into_iter()
                        .any(|x| match_route_addr(&route_iter.dns_domain, &x.name().to_utf8()))
                {
                    continue;
                }
            };
        }

        return route_iter.jump.clone();
    }

    // default out
    OUT.read()[0].clone()
}

#[inline]
fn match_route_addr(route_addr: &RouteAddr, match_obj: &String) -> bool {
    route_addr.empty
        || route_addr.full.is_match(format!(" {} ", match_obj))
        || route_addr.substring.is_match(match_obj)
        || {
            let domain_vec: Vec<&str> = match_obj.split('.').collect();

            for index in 0..domain_vec.len() {
                if route_addr
                    .domain
                    .is_match(format!(" {} ", domain_vec[index..].join(".")))
                {
                    return true;
                }
            }

            false
        }
        || match match_obj.parse::<IpAddr>() {
            Ok(ipaddr) => match ipaddr {
                IpAddr::V4(ip) => route_addr.cidr4.longest_match(ip).is_some(),
                IpAddr::V6(ip) => route_addr.cidr6.longest_match(ip).is_some(),
            },
            Err(_) => false,
        }
        || route_addr.regex.is_match(match_obj.as_str())
}

#[test]
fn test_domain() {
    let domain = "a.b.c.d.com";
    let domain_vec: Vec<&str> = domain.split('.').collect();
    for index in 0..domain_vec.len() {
        println!(" {} ", domain_vec[index..].join("."));
    }
}
