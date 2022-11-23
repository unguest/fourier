use exe::{ImageImportDescriptor};
use exe::pe::{VecPE, PE};
use exe::types::{ImportDirectory, ImportData, CCharString};


pub fn basic_information(binary_path:&String) {
    let image: VecPE = VecPE::from_disk_file(binary_path).unwrap(); // MZ Image

    let modules: Vec<ImageImportDescriptor> = get_modules(image.to_owned());
    let modules_names: Vec<String> = get_modules_names(image.to_owned());
    let function_numbers:i16 = get_image_functions(image.to_owned(), modules)
    .len()
    .try_into()
    .unwrap();

    println!("Arch : {:?}", image.get_arch().unwrap());
    println!("Magic Bytes : {}", image.get_dos_header().unwrap().e_magic);
    println!("Checksum : {}\n", image.calculate_checksum().unwrap());
    println!("Offset to headers : {:?} bytes", image.get_dos_header().unwrap().e_lfanew.0);
    println!("Header size : {} bytes\n", image.calculate_header_size().unwrap());
    //println!("Import hash : {:?}", image.calculate_imphash().unwrap().make_ascii_uppercase());
    println!("Disk size : {} Mb",(image.calculate_disk_size().unwrap() as f32).round()/100000.0);
    println!("Memory size : {} Mb",(image.calculate_memory_size().unwrap() as f32).round()/100000.0);
    println!("Sections : ");
    for section in image.get_section_table().unwrap() {
        println!("\t- {0} ({1:?} bytes, {2:?})", section.name.as_str(), section.size_of_raw_data, section.characteristics);
    }

    
    println!("\nEntry point : 0x{:X?}", image.get_entrypoint().unwrap().0);
    println!("Functions loaded : {0}", function_numbers);
    println!("{0} Imported DLLs :", modules_names.len());


    for module_name in modules_names {

        println!("\t- {}", module_name);
    }

} // basic_information()


pub fn get_modules(mz_image:VecPE) -> Vec<ImageImportDescriptor> {
    let mut imports:Vec<ImageImportDescriptor> = Vec::new();
    let import_directory: ImportDirectory = ImportDirectory::parse(&mz_image).unwrap(); // Imports of the PE File


    for descriptor in import_directory.descriptors {
        imports.push(descriptor.clone());
    }

    imports
} // get_modules


pub fn get_modules_names(mz_image:VecPE) -> Vec<String> {

    let mut modules_names: Vec<String> = Vec::new();

    for module in get_modules(mz_image.to_owned()) {
        modules_names.push(module.get_name(&mz_image).unwrap().as_str().to_string());
    }

    modules_names
} // get_modules_names


pub fn get_module_functions(mz_image:VecPE, module:ImageImportDescriptor) -> Vec<String> {

    let mut functions:Vec<String> = Vec::new();

    for import in module.get_imports(&mz_image).unwrap() {
        match import {
        //ImportData::Ordinal(x) => functions.push(format!("{}", x)),
        ImportData::ImportByName(s) => functions.push(s.to_string()),
        
        ImportData::Ordinal(_) => {
            
        }
    }
    } // for import in module

    functions
}


pub fn get_image_functions(mz_image:VecPE, modules:Vec<ImageImportDescriptor>) -> Vec<String> {

    let mut mz_image_functions: Vec<String> = Vec::new();
    
    for module in modules {
        
        mz_image_functions.append(
            &mut get_module_functions(mz_image.to_owned(), module)
        );

    } // for module in modules

    mz_image_functions

} // get_functions_names