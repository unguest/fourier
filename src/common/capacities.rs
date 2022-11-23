pub fn get_supported_executable_formats() -> Vec<String> {
    let mut supported_executables = Vec::new();
    supported_executables.push(String::from("PE_32"));
    supported_executables.push(String::from("PE_64"));

    supported_executables
}

pub fn print_supported_executables() {
    println!("~> Supported executable formats :");

    for supported_executable_format in get_supported_executable_formats() {
        println!("\t- {0}", supported_executable_format);
    }
}