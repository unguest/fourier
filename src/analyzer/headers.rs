use exe::pe::{PE, VecPE};
use exe::types::{ImportDirectory, ImportData, CCharString};

pub fn basic_information(binary_path:String) {
    let image = VecPE::from_disk_file(binary_path).unwrap(); // MZ Image
    let import_directory = ImportDirectory::parse(&image).unwrap(); // Imports of the PE File
}