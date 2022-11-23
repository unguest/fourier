mod common;
mod analyzer;

fn main() {
    println!("~> Fourier - Reliable analysis");
    println!("~> https://github.com/unguest/fourier");
    println!("~> You are executing version v0.0.1");
    common::capacities::print_supported_executables();
    
    common::commands::command_handler();

} // main
