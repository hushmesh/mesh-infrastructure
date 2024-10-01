//! This crate provides functins for loading data for the mesh build process.

use std::env;
use std::fs;
use std::path::PathBuf;

use common_build_injection::MeshIdentificationData;
use common_types::actors_manifest::ActorsManifest;

/// Load build data from a file.  The file is expected to be in the BUILD_DATA_DIR directory.
pub fn load_build_data_from_file(name: &str) -> MeshIdentificationData {
    let ref dir: PathBuf = env::var_os("BUILD_DATA_DIR").unwrap_or_default().into();
    let path = dir.join(format!("{}-build-data.json", name.to_lowercase()));
    let path = path.to_str().unwrap_or_default().to_owned();
    let data =
        fs::read_to_string(&path).unwrap_or_else(|err| panic!("failed to read {} {}", path, err));
    let build_data: MeshIdentificationData = serde_json::from_str(&data)
        .unwrap_or_else(|err| panic!("failed to parse build data {}: {}", path, err));
    build_data
}

/// load the actors manifest from the actors-manifest.json file.  It contains list of actors to build.
pub fn load_actors_manifest() -> ActorsManifest {
    let manifest_path = "actors-manifest.json";
    let manifest_data = fs::read_to_string(manifest_path)
        .unwrap_or_else(|err| panic!("failed to read {:?} {}", manifest_path, err));
    let actors_manifest: ActorsManifest = serde_json::from_str(&manifest_data)
        .unwrap_or_else(|err| panic!("failed to parse actors manifest: {}", err));
    for actor in &actors_manifest.actors {
        if !actor
            .uns_name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
        {
            panic!("actor name contains invalid characters: {}", actor.uns_name);
        }
    }
    actors_manifest
}
