use super::{Out, OUT, ROUTE};
use crate::*;
use log::*;
use serde::Deserialize;
use std::{
    collections::HashMap,
    io::BufRead,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};
use treebitmap::IpLookupTable;

#[derive(Debug, Clone, Deserialize)]
struct RouteRaw {
    #[serde(default)]
    tag: Vec<String>,
    #[serde(default)]
    network: Vec<String>,
    #[serde(default)]
    saddr: Vec<String>,
    #[serde(default)]
    sport: Vec<usize>,
    #[serde(default)]
    daddr: Vec<String>,
    #[serde(default)]
    dport: Vec<usize>,
    #[serde(default)]
    dns_domain: Vec<String>,

    jump: String,
}

pub(crate) struct RouteAddr {
    pub(crate) full: aho_corasick::AhoCorasick,
    pub(crate) substring: aho_corasick::AhoCorasick,
    pub(crate) domain: aho_corasick::AhoCorasick,
    pub(crate) cidr4: IpLookupTable<Ipv4Addr, ()>,
    pub(crate) cidr6: IpLookupTable<Ipv6Addr, ()>,
    pub(crate) regex: regex::RegexSet,
    pub(crate) empty: bool,
}

pub(crate) struct Route {
    pub(crate) tag: Vec<String>,
    pub(crate) network: Vec<String>,
    pub(crate) saddr: RouteAddr,
    pub(crate) sport: Vec<usize>,
    pub(crate) daddr: RouteAddr,
    pub(crate) dport: Vec<usize>,
    pub(crate) dns_domain: RouteAddr,

    pub(crate) jump: Arc<dyn Out + Send + Sync>,
}

pub(crate) fn route_out_parse(root: &serde_json::Value) {
    let mut jump_map = HashMap::new();

    for iter in root["out"].as_array().expect("out not found") {
        let out = match iter["protocol"].as_str().expect("protocol not found") {
            "origin" => origin::Out::new(iter),
            #[cfg(feature = "private")]
            "stn" => stn::Out::new(iter),
            "socks5" => socks5::Out::new(iter),
            "http" => http::Out::new(iter),
            "drop" => drop::Out::new(iter),
            "dns" => dns::Out::new(iter),
            protocol => panic!("protocol not support: {:?}", protocol),
        };
        OUT.write().push(out.clone());

        jump_map.insert(
            iter["tag"]
                .as_str()
                .expect("route tag not found")
                .to_string(),
            out,
        );
    }

    if root["route"].as_array().is_some() {
        for iter in root["route"].as_array().unwrap() {
            let route: RouteRaw = serde_json::from_value(iter.clone()).unwrap();
            let saddr = parse_addr(&route.saddr);
            let daddr = parse_addr(&route.daddr);
            let dns_domain = parse_addr(&route.dns_domain);

            ROUTE.write().push(Route {
                tag: route.tag,
                network: route.network,
                saddr,
                sport: route.sport,
                daddr,
                dport: route.dport,
                dns_domain,
                jump: jump_map
                    .get(&route.jump)
                    .expect("route jump not found")
                    .clone(),
            });
        }
    }
}

fn parse_addr(elems: &Vec<String>) -> RouteAddr {
    #[inline]
    fn read_to_vec(
        elem: &String,
        full_vec: &mut Vec<String>,
        substring_vec: &mut Vec<String>,
        domain_vec: &mut Vec<String>,
        cidr4: &mut IpLookupTable<Ipv4Addr, ()>,
        cidr6: &mut IpLookupTable<Ipv6Addr, ()>,
        regex_vec: &mut Vec<String>,
    ) {
        let mut addr_iter = elem.as_str().split_whitespace();
        match addr_iter.next().expect("invalid route addr") {
            "full" => full_vec.push(format!(
                " {} ",
                addr_iter.next().expect("invalid route addr")
            )),
            "substring" => {
                substring_vec.push(addr_iter.next().expect("invalid route addr").to_string())
            }
            "domain" => domain_vec.push(format!(
                " {} ",
                addr_iter.next().expect("invalid route addr")
            )),
            "cidr" => {
                let cidr_vec: Vec<&str> = addr_iter
                    .next()
                    .expect("invalid route cidr")
                    .split('/')
                    .collect();
                match cidr_vec[0].parse::<IpAddr>().expect("invalid route cidr") {
                    IpAddr::V4(ip) => {
                        cidr4.insert(ip, cidr_vec[1].parse().expect("invalid route cidr"), ());
                    }
                    IpAddr::V6(ip) => {
                        cidr6.insert(ip, cidr_vec[1].parse().expect("invalid route cidr"), ());
                    }
                }
            }
            "regex" => regex_vec.push(addr_iter.next().expect("invalid route addr").to_string()),
            invalid => warn!("{} not support", invalid),
        };
    }

    let mut full_vec = Vec::new();
    let mut substring_vec = Vec::new();
    let mut domain_vec = Vec::new();
    let mut cidr4 = IpLookupTable::new();
    let mut cidr6 = IpLookupTable::new();
    let mut regex_vec = Vec::new();

    for elem in elems {
        if elem.contains("file ") {
            let file = std::fs::File::open(elem[5..].to_string())
                .expect(format!("failed to open {}", elem[5..].to_string()).as_str());
            for line in std::io::BufReader::new(file).lines() {
                match line {
                    Ok(line) => read_to_vec(
                        &line,
                        &mut full_vec,
                        &mut substring_vec,
                        &mut domain_vec,
                        &mut cidr4,
                        &mut cidr6,
                        &mut regex_vec,
                    ),
                    Err(e) => warn!("{}", e),
                }
            }
        } else {
            read_to_vec(
                elem,
                &mut full_vec,
                &mut substring_vec,
                &mut domain_vec,
                &mut cidr4,
                &mut cidr6,
                &mut regex_vec,
            )
        }
    }

    RouteAddr {
        full: aho_corasick::AhoCorasick::new(full_vec),
        substring: aho_corasick::AhoCorasick::new(substring_vec),
        domain: aho_corasick::AhoCorasick::new(domain_vec),
        cidr4,
        cidr6,
        regex: regex::RegexSet::new(regex_vec).expect("can't generate RegexSet"),
        empty: elems.len() == 0,
    }
}
