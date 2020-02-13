mod certificate_manager;
use serde::{Deserialize};

// list of (dirs to copy keys to
// systemd service names)
#[derive(Debug, Deserialize)]
struct Config {
    domain: String,

}

fn main() {

    //parse config file

    loop{
        //count valid days left
        //to duration (clip 0-...)

        //wait for duration
        //update cert
        //distribute cert

        //restart (systemd) services
        //TODO use std::command
    }
}
