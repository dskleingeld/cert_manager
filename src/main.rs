use cert_manager as cert;
use cert_manager::am_root;

use serde::{Serialize, Deserialize};
use serde_yaml;
use log::{self, info, error, warn};
use structopt::StructOpt;

use std::fs;
use std::path::{Path};//, PathBuf};
use std::time::Duration;
use std::thread;
use std::process::Command;
use std::sync::{Mutex, Arc};
use std::io::{self, Read};

const APP_NAME: &str = "cert-manager";

#[derive(StructOpt)]
#[structopt(name = "basic")]
struct Opt {
    /// Internal port to which external port 80 has been forwarded to
    #[structopt(short, long)]
    port: u32,

    /// Log level, options: info, warn, error
    #[structopt(short, long)]
    log: log::Level,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct Config {
    domain: String,
    unit_files: Vec<String>,
}

fn update_cert(domain: &str, dir: &Path, port: u32) -> i64 {
    cert::generate_and_sign_keys(APP_NAME, domain, dir, false, port)
        .unwrap();
    let days = cert::valid_days_left(APP_NAME, domain, dir)
        .unwrap()
        .unwrap();
    info!("generated new certificate valid for {} days", days);
    days
}

fn restart_services(units: &[String]){
    for unit in units {
        let output = Command::new("systemctl")
            .arg("restart")
            .arg(unit.as_str())
            .output()
            .unwrap();
        
        if !output.status.success() {
            error!("could not restart system service: {:?}", output);
        }
    }
}


fn main() -> Result<(), std::io::Error> {
    let done = Arc::new(Mutex::new(()));
    let done_copy = done.clone();
    let not_done = done_copy.lock().unwrap();
    
    let opt = Opt::from_args();
    dbg!(&opt.log);
    simple_logger::init_with_level(opt.log).unwrap();
    dbg!();

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
    let config = serde_yaml::from_reader(f);
    if config.is_err() {
        error!("Could not understand config, stopping");
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput, 
            "can not parse config"));        
    }
    let config: Config = config.unwrap();

    let keys = Path::new("keys");
    if !keys.exists() {
        fs::create_dir(keys).unwrap();
    }

    let days_left =
    match cert::valid_days_left(APP_NAME, &config.domain, &keys).unwrap() {
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

    let sleep_thread = thread::spawn(move || {    
        loop {
            thread::sleep(next_update);

            let days_left = update_cert(&config.domain, &keys, opt.port);
            info!("updated certificate for: {}", &config.domain);

            //restart (systemd) services
            restart_services(&config.unit_files);
            
            //update time to sleep        
            let days_left = if days_left > 0 {days_left as u64} else {0 as u64};
            next_update = Duration::from_secs((days_left-1)*3600*24);
        }
    });

    let stdin = io::stdin();
    let mut handle = stdin.lock();
    handle.read(&mut [1]).unwrap();

    drop(not_done);
    sleep_thread.join().unwrap();
    Ok(())
}