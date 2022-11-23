use std::io::{
    stdin,
    stdout, Write,

};

use std::process::exit;

use exe::VecPE;

use crate::analyzer;
use crate::analyzer::apidetect::analyze_all;
use crate::analyzer::headers::{get_image_functions, get_modules};

pub fn command_handler() {

    let mut binary_path:String = String::new();
    let mut user_input:String = String::new();

    loop {

        print!("~> ");
        _ = stdout().flush();

        match stdin()
            .read_line(&mut user_input) {
            Err(_) => {
                println!("[ ! ] ERROR : Could not read user input. Are you using QubesOS ? ");
                exit(0);
            }
            _ => {}
        } // match stdin

        let splitted_input = user_input.trim().split(" ").collect::<Vec<&str>>();

        match splitted_input.first().unwrap(){

            &"a" | &"anal" | &"analyze" => {
                let mz_image: VecPE = VecPE::from_disk_file(binary_path.to_owned()).unwrap();
                let modules = get_modules(mz_image.to_owned());

                let fn_names = get_image_functions(mz_image, modules);

                analyze_all(fn_names.to_owned());
            }

            &"bi" | &"basic_info" | &"basic_information" => {
                analyzer::headers::basic_information(&binary_path);
            }

            &"cl" | &"clear" => {
                print!("\x1B[2J\x1B[1;1H");
            }

            &"da" | &"dant" | &"detect_antidebug" => {
                let mz_image: VecPE = VecPE::from_disk_file(binary_path.to_owned()).unwrap();
                let modules = get_modules(mz_image.to_owned());

                let fn_names = get_image_functions(mz_image, modules);
                let de_functions = analyzer::apidetect::detect_antidebug(fn_names);

                if de_functions.len() > 0 {
                    println!("[ * ] Found {0} functions that may be used for anti-debugging purposes in {1} : ", de_functions.len(), binary_path);

                    for function in de_functions {
                        println!("\t- {0}", function);
                    } // For function in de_functions

                } else {// If any de_function else
                    println!("[ * ] No function used for anti-debgging purposes detected in {0}.", binary_path);
                } // if no de_function
            }

            &"den" | &"detect_enumeration" => {

                let mz_image: VecPE = VecPE::from_disk_file(binary_path.to_owned()).unwrap();
                let modules = get_modules(mz_image.to_owned());

                let fn_names = get_image_functions(mz_image, modules);
                let de_functions = analyzer::apidetect::detect_enumeration(fn_names);

                if de_functions.len() > 0 {
                    println!("[ * ] Found {0} functions that may be used for enumeration purposes in {1} : ", de_functions.len(), binary_path);

                    for function in de_functions {
                        println!("\t- {0}", function);
                    } // For function in de_functions

                } else {// If any de_function else
                    println!("[ * ] No function used for enumeration purposes detected in {0}.", binary_path);
                } // if no de_function
            } // detect enumeration command


            &"dev" | &"detect_evasion" => {
                let mz_image: VecPE = VecPE::from_disk_file(binary_path.to_owned()).unwrap();
                let modules = get_modules(mz_image.to_owned());

                let fn_names = get_image_functions(mz_image, modules);
                let de_functions = analyzer::apidetect::detect_evasion(fn_names);

                if de_functions.len() > 0 {
                    println!("[ * ] Found {0} functions that may be used for evasion purposes in {1} : ", de_functions.len(), binary_path);

                    for function in de_functions {
                        println!("\t- {0}", function);
                    } // For function in de_functions

                } else {// If any de_function else
                    println!("[ * ] No function used for evasion purposes detected in {0}.", binary_path);
                } // if no de_function
            }

            
            &"dinj" | &"detect_injection" => {
                let mz_image: VecPE = VecPE::from_disk_file(binary_path.to_owned()).unwrap();
                let modules = get_modules(mz_image.to_owned());

                let fn_names = get_image_functions(mz_image, modules);
                let de_functions = analyzer::apidetect::detect_injection(fn_names);

                if de_functions.len() > 0 {
                    println!("[ * ] Found {0} functions that may be used for injection purposes in {1} : ", de_functions.len(), binary_path);

                    for function in de_functions {
                        println!("\t- {0}", function);
                    } // For function in de_functions

                } else {// If any de_function else
                    println!("[ * ] No function used for injectin detected purposes in {0}.", binary_path);
                } // if no de_function
            }

            &"dint" | &"detect_internet" => {
                let mz_image: VecPE = VecPE::from_disk_file(binary_path.to_owned()).unwrap();
                let modules = get_modules(mz_image.to_owned());

                let fn_names = get_image_functions(mz_image, modules);
                let de_functions = analyzer::apidetect::detect_internet(fn_names);

                if de_functions.len() > 0 {
                    println!("[ * ] Found {0} functions that may be used for internet communication purposes in {1} : ", de_functions.len(), binary_path);

                    for function in de_functions {
                        println!("\t- {0}", function);
                    } // For function in de_functions

                } else {// If any de_function else
                    println!("[ * ] No function used for internet communication purposes in {0}.", binary_path);
                } // if no de_function
            }

            &"ds" | &"detect_spying" => {
                let mz_image: VecPE = VecPE::from_disk_file(binary_path.to_owned()).unwrap();
                let modules = get_modules(mz_image.to_owned());

                let fn_names = get_image_functions(mz_image, modules);
                let de_functions = analyzer::apidetect::detect_spying(fn_names);

                if de_functions.len() > 0 {
                    println!("[ * ] Found {0} functions that may be used for spying purposes in {1} : ", de_functions.len(), binary_path);

                    for function in de_functions {
                        println!("\t- {0}", function);
                    } // For function in de_functions

                } else {// If any de_function else
                    println!("[ * ] No function used for enumeration spying purposes in {0}.", binary_path);
                } // if no de_function
            }

           &"dr" | &"drans" | &"detect_ransomware" => {
            let mz_image: VecPE = VecPE::from_disk_file(binary_path.to_owned()).unwrap();
            let modules = get_modules(mz_image.to_owned());

            let fn_names = get_image_functions(mz_image, modules);
            let de_functions = analyzer::apidetect::detect_ransomware(fn_names);

            if de_functions.len() > 0 {
                println!("[ * ] Found {0} functions that may be used in ransomwares in {1} : ", de_functions.len(), binary_path);

                for function in de_functions {
                    println!("\t- {0}", function);
                } // For function in de_functions

            } else {// If any de_function else
                println!("[ * ] No function used in ransomwares detected in {0}.", binary_path);
            } // if no de_function
           }

           &"dh" | &"detect_helpers" => {
            let mz_image: VecPE = VecPE::from_disk_file(binary_path.to_owned()).unwrap();
            let modules = get_modules(mz_image.to_owned());

            let fn_names = get_image_functions(mz_image, modules);
            let de_functions = analyzer::apidetect::detect_helpers(fn_names);

            if de_functions.len() > 0 {
                println!("[ * ] Found {0} functions that may be used as helpers in {1} : ", de_functions.len(), binary_path);

                for function in de_functions {
                    println!("\t- {0}", function);
                } // For function in de_functions

            } else {// If any de_function else
                println!("[ * ] No function used as helpers detected in {0}.", binary_path);
            } // if no de_function
           }
            
            &"hd" | &"headers" => {
                // TODO : print the headers of the provided binary file
            }

            &"ld" | &"load" => {

                if splitted_input.len() > 1 {
                    binary_path = splitted_input.get(1).unwrap().to_string();

                    if std::path::Path::new(&binary_path).exists() {
                        println!("[ * ] Loaded {}", binary_path);
                    } else {
                        println!("[ ! ] File {0} does not exists", binary_path);
                        binary_path.clear();
                    }
                } else {
                    println!("[ ! ] Please provide a binary path")
                }

            }

            &"lf" | &"list_functions" => {
                let mz_image = VecPE::from_disk_file(&binary_path).unwrap();
                let modules = analyzer::headers::get_modules(mz_image.to_owned());
                let functions = analyzer::headers::get_image_functions(mz_image.to_owned(), modules);


                println!("[ * ] Diplaying {0} functions :", functions.len());

                for function in functions {
                    println!("\t- {0}", function);
                }
            }

            &"exit" => {
                exit(0);
            }

            _ => {
                println!("[ ! ] Command {0} not found.", user_input.trim());
            }

        } // match user_input

        user_input.clear();

    } // while user_input != String::from("exit")
    
} // pub fn command_handler()