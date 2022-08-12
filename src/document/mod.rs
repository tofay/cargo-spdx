//! Module for working with SPDX documents.

use crate::git::get_current_user;
use anyhow::{Context, Result};
use cargo_metadata::camino::Utf8PathBuf;
use sha1::{Digest, Sha1};
use sha2::Sha256;
use spdx_rs::models::{
    Algorithm, Checksum, CreationInfo, ExternalPackageReference, ExternalPackageReferenceCategory,
    FileInformation, FileType, PackageInformation, SpdxExpression,
};
use std::{
    fs::{self},
    io,
};

pub const NOASSERTION: &str = "NOASSERTION";

/// Identify the creator(s) of the SBOM.
pub fn get_creation_info() -> Result<CreationInfo> {
    let mut creators = vec![];

    if let Ok(user) = get_current_user() {
        creators.push(format!(
            "Persion: {}{}",
            user.name,
            user.email.map(|s| format!(" ({})", s)).unwrap_or_default()
        ));
    }

    creators.push("Tool: cargo-spdx 0.1.0".to_string());

    Ok(CreationInfo {
        license_list_version: None,
        creators,
        created: chrono::offset::Utc::now(),
        creator_comment: None,
    })
}

pub(crate) trait PackageInformationExt {
    fn from_metadata_package(package: &cargo_metadata::Package) -> Self;
}

impl PackageInformationExt for PackageInformation {
    fn from_metadata_package(package: &cargo_metadata::Package) -> Self {
        PackageInformation {
            package_name: package.name.to_string(),
            package_spdx_identifier: format!("SPDXRef-{}-{}", package.name, package.version),
            package_version: Some(package.version.to_string()),
            package_file_name: None,
            package_supplier: None,
            package_originator: None,
            package_download_location: NOASSERTION.to_string(),
            files_analyzed: None,
            package_verification_code: None,
            package_checksum: Vec::new(),
            package_home_page: package.homepage.clone(),
            source_information: None,
            concluded_license: SpdxExpression::parse("NOASSERTION").unwrap(),
            declared_license: SpdxExpression::parse("NOASSERTION").unwrap(),
            copyright_text: NOASSERTION.to_string(),
            package_summary_description: None,
            package_comment: None,
            external_reference: vec![ExternalPackageReference {
                reference_category: ExternalPackageReferenceCategory::PackageManager,
                reference_type: "purl".to_string(),
                reference_locator: format!("pkg:cargo/{}@{}", package.name, package.version),
                reference_comment: None,
            }],
            annotations: Vec::new(),
            package_attribution_text: Vec::new(),
            files: Vec::new(),
            comments_on_license: None,
            all_licenses_information_from_files: Vec::new(),
            package_detailed_description: None,
        }
    }
}

pub(crate) trait FileInformationExt {
    fn try_from_binary(path: &Utf8PathBuf) -> Result<FileInformation>;
}

impl FileInformationExt for FileInformation {
    fn try_from_binary(path: &Utf8PathBuf) -> Result<Self> {
        let file_name = path.file_name().unwrap();
        let spdxid = format!("SPDXRef-File-{}", file_name);
        Ok(FileInformation {
            file_attribution_text: None,
            file_checksum: calculate_checksums(path)?,
            file_comment: None,
            copyright_text: NOASSERTION.to_string(),
            file_name: file_name.to_string(),
            file_type: vec![FileType::Binary],
            comments_on_license: None,
            concluded_license: SpdxExpression::parse("NOASSERTION").unwrap(),
            license_information_in_file: Vec::new(),
            file_notice: None,
            file_spdx_identifier: spdxid,
            file_contributor: Vec::new(),
        })
    }
}

/// Generate SHA1 and SHA256 checksums for a given file
/// SPDX spec mandates SHA1
fn calculate_checksums(path: &Utf8PathBuf) -> Result<Vec<Checksum>> {
    let mut file = fs::File::open(path).context(format!("Failed to open {}", path))?;
    let mut sha256 = Sha256::new();
    let sha1 = Sha1::new();
    io::copy(&mut file, &mut sha256)?;
    let sha256_hash = sha256.finalize();
    let sha1_hash = sha1.finalize();
    Ok(vec![
        Checksum {
            algorithm: Algorithm::SHA1,
            value: hex::encode(&sha1_hash),
        },
        Checksum {
            algorithm: Algorithm::SHA256,
            value: hex::encode(&sha256_hash),
        },
    ])
}
