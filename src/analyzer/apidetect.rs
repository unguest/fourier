use std::fs;

pub fn detect_malused_functions(function_purpose:&str, function_names:Vec<String>) -> Vec<String> {
    let file = fs::File::open("config/winapi.json")
        .expect("winapi.json is not readable.");


    let json: serde_json::Value = serde_json::from_reader(file)
        .expect("winapi.json is not properly formatted.");

    let malused_functions = json.get(function_purpose)
        .expect("winapi.json has no 'Enuemeration' key.");
  
    let mut detected_functions:Vec<String> = Vec::new();

    for function in malused_functions.as_array().unwrap() {
        if function_names.iter().any(|e| e == function) { // Look if any function in the mz image is used for indicated purpose
            detected_functions.push(function.to_string());
        }
    }

    detected_functions

} // detect_malused_functions

pub fn analyze_all(function_names:Vec<String>) {
    let adbg_fn = detect_antidebug(function_names.to_owned());
    let enum_fn = detect_enumeration(function_names.to_owned());
    let evas_fn = detect_evasion(function_names.to_owned());
    let injc_fn = detect_injection(function_names.to_owned());
    let itnt_fn = detect_internet(function_names.to_owned());
    let rsmw_fn = detect_ransomware(function_names.to_owned());
    let hlpr_fn = detect_helpers(function_names.to_owned());
    
    
    let total_fn = adbg_fn.len() + enum_fn.len() + evas_fn.len() + injc_fn.len() + itnt_fn.len() + rsmw_fn.len() + hlpr_fn.len();

    println!("[ * ] A total of {0}/{1} potentially misused functions has been found :", total_fn, function_names.len());

    println!("\t- {0}/{1} functions used for anti-debugging", adbg_fn.len(), function_names.len());
    println!("\t- {0}/{1} functions used for enumeration", enum_fn.len(), function_names.len());
    println!("\t- {0}/{1} functions used for evasion", evas_fn.len(), function_names.len());
    println!("\t- {0}/{1} functions used for injection", injc_fn.len(), function_names.len());
    println!("\t- {0}/{1} functions used for internet communication", itnt_fn.len(), function_names.len());
    println!("\t- {0}/{1} functions used by ransomwares", rsmw_fn.len(), function_names.len());
    println!("\t- {0}/{1} helpers", hlpr_fn.len(), function_names.len());

}

pub fn detect_enumeration(function_names:Vec<String>) -> Vec<String> {
    detect_malused_functions(&"Enumeration", function_names.to_owned())
}

pub fn detect_injection(function_names:Vec<String>) -> Vec<String> {
    detect_malused_functions(&"Injection", function_names.to_owned())
}

pub fn detect_evasion(function_names:Vec<String>) -> Vec<String> {
    detect_malused_functions(&"Evasion", function_names.to_owned())
}

pub fn detect_spying(function_names:Vec<String>) -> Vec<String> {
    detect_malused_functions(&"Spying", function_names.to_owned())
}

pub fn detect_internet(function_names:Vec<String>) -> Vec<String> {
    detect_malused_functions(&"Internet", function_names.to_owned())
}

pub fn detect_antidebug(function_names:Vec<String>) -> Vec<String> {
    detect_malused_functions(&"Antidebug", function_names.to_owned())
}

pub fn detect_ransomware(function_names:Vec<String>) -> Vec<String> {
    detect_malused_functions(&"Ransomware", function_names.to_owned())
}

pub fn detect_helpers(function_names:Vec<String>) -> Vec<String> {
    detect_malused_functions(&"Helpers", function_names.to_owned())
}
