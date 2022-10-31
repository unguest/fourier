use std::io::{
    stdin,
    stdout,

};

use std::process::exit;

pub fn command_handler() {
    let mut user_input:String = String::new();

    while user_input != String::from("exit") {

        match stdin()
            .read_line(&mut user_input) {
            Err(_) => {
                println!("[ ! ] ERROR : Could not read user input. Are you using QubesOS ? ");
                exit(0);
            }
            _ => {}
        } // match stdin

        match user_input.as_str() {
            "bi" | "basic info" | "basic information" => {
                // TODO : print basic information of the provided binary file
            }

            "hd" | "headers" => {
                // TODO : print the headers of the provided binary file
            }

            "a" | "anal" | "analyze" => {
                // TODO : launch a full analysis of the binary
            }
            _ => {
                println!("~> Command {0} not found.", user_input);
            }

        } // match user_input
    } // while user_input != String::from("exit")
    
} // pub fn command_handler()