use acme_lib::{Directory, DirectoryUrl};
use acme_lib::persist::FilePersist;
use acme_lib::create_p384_key;

use actix_web::{HttpServer, App, Responder, HttpResponse};
use actix_files as fs;
use actix_rt;

use log::{warn};

use std::env;
use std::sync::mpsc;
use std::fs::create_dir_all;
use std::fs::remove_dir_all;
use std::io;
use std::path::Path;
use std::thread;

#[derive(Debug)]
pub enum Error {
	WriteError(std::io::Error),
	LibError(acme_lib::Error),
	Timeout,
}

impl From<acme_lib::Error> for Error {
	fn from(err: acme_lib::Error) -> Self {
		Error::LibError(err)
	}
}
impl From<std::io::Error> for Error {
	fn from(err: std::io::Error) -> Self {
		Error::WriteError(err)
	}
}

pub fn valid_days_left(
	application: &str,
	domain: &str,
	dir: &Path)
 -> Result<Option<i64>, Error> {

	let url = DirectoryUrl::LetsEncryptStaging; //for dev, higher rate limit
	//let url = DirectoryUrl::LetsEncrypt; //only for deployment (LOW RATE LIMIT)
	let persist = FilePersist::new(dir);
	let dir = Directory::from_url(persist, url).unwrap();
	let account = dir.account(&format!("{}@{}", application, domain)).unwrap();

	if let Some(cert) = account.certificate(domain)?{
		Ok(Some(cert.valid_days_left()))
	} else {
		Ok(None)
	}
}

pub fn generate_and_sign_keys_guided(
	application: &str,
	domain: &str,
	dir: &Path,
	staging: bool,
) -> Result<(), Error> {

	let port = get_port().unwrap();
	generate_and_sign_keys(
		application,
		domain,
		dir,
		staging,
		port)
}

/// if guided is true this will add manual checks to verify the challange
/// server is reachable and ask for an port
pub fn generate_and_sign_keys(
	application: &str,
	domain: &str,
	dir: &Path,
	staging: bool,
	port: u32,
) -> Result<(), Error> {

	let www_domain = format!("www.{}",&domain);
	let subdomains = [www_domain.as_str()];
	if !Path::new(dir).exists(){
		create_dir_all(dir).unwrap();
	}

	let url = if staging {
        warn!("running against staging envirment meant for development and testing, \
               output will not be signed with by a known CA. set staging to false \
               to get a \"real\" certifacte");
        DirectoryUrl::LetsEncryptStaging //for dev, higher rate limit
    } else {
        DirectoryUrl::LetsEncrypt //only for deployment (LOW RATE LIMIT)
    }; 

	let persist = FilePersist::new(dir);
	let dir = Directory::from_url(persist, url).unwrap();
	let account = dir.account(&format!("{}@{}", application, domain)).unwrap();
	let mut ord_new = account.new_order(domain, &subdomains).unwrap();//&domains).unwrap();

	//create dir structure for http challanges
	if !Path::new(".tmp/www/.well-known/acme-challenge").exists(){
		create_dir_all(".tmp/www/.well-known/acme-challenge").unwrap();
	}
	// start file server for http challange
	let server = host_server(port).expect("needs to be ran as root");
	/*if guided {
		println!("check if the server is reachable and or press enter to continue");
		let mut input = String::new();
		std::io::stdin().read_line(&mut input).unwrap();
	}*/

	let mut attempt: u8 = 0;
	let ord_csr =  loop { 
		// If the ownership of the domain(s) have already been
		// authorized in a previous order, we might be able to
		// skip validation. The ACME API provider decides.	
		if let Some(ord_csr) = ord_new.confirm_validations() {
            stop_server(server);
			remove_dir_all(".tmp/www/").unwrap();
			break ord_csr;
		} 
		if attempt > 5 {
            stop_server(server);
			remove_dir_all(".tmp/www/").unwrap();
			return Err(Error::Timeout);
		}

		// Get the possible authorizations
		let auths = ord_new.authorizations().unwrap();
		for chall in auths.iter().map(|a| a.http_challenge()){
			// The token is the filename.
			let token = chall.http_token();
			let path = format!(".tmp/www/.well-known/acme-challenge/{}", token);
			let proof = chall.http_proof();
	
			std::fs::write(path, &proof).unwrap();
			chall.validate(5000).unwrap();
			ord_new.refresh().unwrap();
		}

		attempt+=1;
	};

	//use the certificate signing request from the
	//succeeded http challange above to create a signed key
	let pkey_pri = create_p384_key();
	let ord_cert = ord_csr.finalize_pkey(pkey_pri, 5000).unwrap();
	let _cert = ord_cert.download_and_save_cert().unwrap();
	Ok(())
}

pub fn stop_server(server_handle: actix_web::dev::Server){
	let mut rt = actix_rt::Runtime::new().unwrap();
	rt.block_on(server_handle.stop(false));
}

pub fn test_server_up_down(){
	let server_handle = host_server(80).unwrap();
	stop_server(server_handle);
}

//handles only requests for certificate challanges
pub fn host_server(port: u32) -> Result<actix_web::dev::Server, ()> {
	
	let socket = format!("0.0.0.0:{}", port);

	let (tx, rx) = mpsc::channel();
	thread::spawn(move || {
		let sys = actix_rt::System::new("http-server");
		let addr = HttpServer::new(|| 
			App::new()
			.route("/", actix_web::web::get().to(index))
			.service(fs::Files::new("/.well-known/acme-challenge", "./.tmp/www/.well-known/acme-challenge"))
		)
		.workers(1)
		.bind(&socket).expect(&format!("Can not bind to {}",socket))
		.shutdown_timeout(5)    // <- Set shutdown timeout to 5 seconds
		.run();

		let _ = tx.send(addr);
		let _ = sys.run();
		dbg!("thread done");
	});
	let handle = rx.recv().unwrap();
	Ok(handle)
}


async fn index() -> impl Responder {
    HttpResponse::Ok().body("Hello world!, the certificate challange server is up")
}

pub fn am_root() -> bool {
	match env::var("USER") {
		Ok(val) => val == "root",
		Err(_e) => false,
	}
}

fn get_port() -> Result<u32, ()> {
	if am_root() {
		//ask if port 80 has been forwarded
		println!("has the external (WAN) port 80 been forwarded to this machines port 80? (y/N)");
		let mut input_text = String::new();
		io::stdin()
			.read_line(&mut input_text)
			.expect("failed to read from stdin");

		let trimmed = input_text.trim();
		if trimmed == "y" {
			Ok(80)
		} else {
			Err(())
		}
	} else {
		println!("please input a internal (LAN) port to which the external (WAN) port 80 has been forwarded:");
		let mut input_text = String::new();
		io::stdin()
			.read_line(&mut input_text)
			.expect("failed to read from stdin");

		let trimmed = input_text.trim();
		match trimmed.parse::<u32>() {
			Ok(i) => Ok(i),
			Err(..) => {
				println!("that was not an integer: {}", trimmed);
				Err(())
			}
		}
	}
}