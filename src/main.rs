// mod dns;
// mod drop;
mod misc;
mod origin;
// mod resolve;
mod http;
mod route;
mod socks5;
#[cfg(feature = "private")]
mod stn;
#[cfg(not(target_os = "windows"))]
mod tproxy;

use log::*;
use log4rs::{
    append::{console::ConsoleAppender, rolling_file::policy::compound},
    config,
};
// use resolve::init_resolve;
use std::{env, fs::File, io::prelude::*};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    if args.len() != 3 || args[1].as_str() != "-c" {
        show_help();
        return Ok(());
    }

    let file = File::open(args[2].as_str())?;
    let root: serde_json::Value = serde_json::from_reader(file)?;

    do_setting(&root["setting"])?;
    info!("setting done");

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(tokio_based_start(&root));

    Ok(())
}

// uid/gid iptables match
async fn tokio_based_start(root: &serde_json::Value) {
    // init_resolve(&root["resolve"]).unwrap();

    route::route_out_parse(root);
    info!("route and out initialized");

    for iter in root["in"].as_array().expect("in not found") {
        match iter["protocol"].as_str() {
            Some("http") => tokio::spawn(http::In::start(iter.clone())),
            Some("socks5") => tokio::spawn(socks5::In::start(iter.clone())),
            #[cfg(feature = "private")]
            Some("stn") => tokio::spawn(stn::In::start(iter.clone())),
            #[cfg(not(target_os = "windows"))]
            Some("tproxy") => tokio::spawn(tproxy::In::start(iter.clone())),
            protocol => panic!("protocol not support: {:?}", protocol),
        };
    }
    info!("in initialized");

    // block forever
    tokio::sync::Notify::new().notified().await;
}

fn show_help() {
    println!("stn version:{}", env!("CARGO_PKG_VERSION"));
    println!("  -c [file]     specify the configuration file to start");
    println!("  -h            show this message");
}

fn do_setting(root: &serde_json::Value) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(not(target_os = "windows"))]
    unsafe {
        if let Some(gid) = root["gid"].as_u64() {
            assert!(libc::setgid(gid as _) == 0);
        }
        if let Some(uid) = root["uid"].as_u64() {
            assert!(libc::setuid(uid as _) == 0);
        }

        if let Some(true) = root["daemon"].as_bool() {
            assert!(libc::daemon(1, 1) == 0);
        }
    }

    let pid_file = root["pid_file"].as_str().unwrap_or_else(|| "");
    if pid_file != "" {
        let mut file = File::create(pid_file)?;
        write!(file, "{}", std::process::id())?;
    }

    let log_level = match root["log_level"].as_str() {
        Some("debug") => LevelFilter::Debug,
        Some("info") => LevelFilter::Info,
        Some("warn") => LevelFilter::Warn,
        Some("error") => LevelFilter::Error,
        Some(_) => Err("unsupport log level")?,
        None => LevelFilter::Error,
    };

    let log_encoder = Box::new(log4rs::encode::pattern::PatternEncoder::new(
        "{d(%m-%d %H:%M:%S%.6f)}   {({l}):5}   {({f}:{L}):>30}   {m}{n}",
    ));

    let log_appender: Box<dyn log4rs::append::Append> = match root["log_file"].as_str() {
        Some("") | Some("stdout") | None => {
            Box::new(ConsoleAppender::builder().encoder(log_encoder).build())
        }
        Some(file) => {
            let file_max = root["log_file_max"].as_u64().unwrap_or_else(|| 1024);
            Box::new(
                log4rs::append::rolling_file::RollingFileAppender::builder()
                    .encoder(log_encoder)
                    .build(
                        file,
                        Box::new(compound::CompoundPolicy::new(
                            Box::new(compound::trigger::size::SizeTrigger::new(file_max * 1024)),
                            Box::new(compound::roll::delete::DeleteRoller::new()),
                        )),
                    )?,
            )
        }
    };

    let log_config = config::Config::builder()
        .appender(config::Appender::builder().build("root", log_appender))
        .build(config::Root::builder().appender("root").build(log_level))?;

    log4rs::init_config(log_config)?;

    Ok(())
}
