mod certificate_manager;
use certificate_manager as cert;
use certificate_manager::am_root;

use serde::{Serialize, Deserialize};
use serde_yaml;
use actix_rt;
use log::{self, info, error, warn};

use std::fs;
use std::path::{Path};//, PathBuf};
use std::time::Duration;
use std::thread;
use std::process::Command;

const APP_NAME: &str = "cert-manager";

#[derive(Debug, Serialize, Deserialize, Default)]
struct Config {
    domain: String,
    unit_files: Vec<String>,
}

async fn update_cert(domain: &str, dir: &Path) -> i64 {
    cert::generate_and_sign_keys(APP_NAME, domain, dir).await
        .unwrap();
    let days = cert::valid_days_left(APP_NAME, domain, dir).await
        .unwrap()
        .unwrap();
    info!("generated new certificate valid for {} days", days);
    days
}

fn restart_services(units: &Vec<String>){
    for unit in units {
        let output = Command::new("systemctl")
            .arg("restart")
            .arg(unit.as_str())
            .output()
            .unwrap();
        dbg!(output);
    }
}

#[actix_rt::main]
async fn main() -> Result<(), std::io::Error> {
    simple_logger::init_with_level(log::Level::Info).unwrap();

    if !am_root(){
        error!("needs to be ran under root user, stopping");
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied, 
            "not under root"));
    }

    let config = Path::new("config.yaml");
    if !config.exists(){
        let f = fs::File::create("config.yaml").unwrap();
        serde_yaml::to_writer(f, &Config::default()).unwrap();
        error!("Config file not found (created empty one for you), stopping");
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound, 
            "config file not found"));
    }

    let f = fs::File::open("config.yaml").unwrap();
    let config: Config = serde_yaml::from_reader(f).unwrap();

    let keys = Path::new("keys");
    if !keys.exists() {
        fs::create_dir(keys).unwrap();
    }

    let days_left =
    match cert::valid_days_left(APP_NAME, &config.domain, &keys).await.unwrap() {
        None => {
            warn!("No certificate found, immediatly updating");
            0 }//force immediate update
        Some(days) => {
            info!("Found certificate still valid for {} days", days);
            days }
    };

    let mut next_update = if days_left > 1 {
        Duration::from_secs((days_left as u64-1)*3600*24)
    } else {
        Duration::from_secs(0)
    };

    loop {
        thread::sleep(next_update);

        let days_left = update_cert(&config.domain, &keys).await;
        info!("updated certificate for: {}", &config.domain);

        //restart (systemd) services
        restart_services(&config.unit_files);
        
        //update time to sleep        
        let days_left = if days_left > 0 {days_left as u64} else {0 as u64};
        next_update = Duration::from_secs((days_left-1)*3600*24);
    }
}

