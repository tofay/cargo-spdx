//! Writes the flat file format out.
use anyhow::Result;
use spdx_rs::models::SPDX;
use std::io::Write;

/// Convenience macro to provide uniform field-writing syntax.
///
/// This macro exists to make the `write_to_disk` method body cleaner.
/// It provides a uniform calling construct to write out regular, optional,
/// and iterable fields.
///
/// Making it easier to skim the code at the call-sites it intended to make
/// the code more closely resemble the structure of the file being written out.
macro_rules! write_field {
    // Write out a single field.
    ( $f:ident, $fmt:literal, $field:expr ) => {
        writeln!($f, $fmt, $field)?
    };

    // Write out an optional field.
    ( @opt, $f:ident, $fmt:literal, $field:expr ) => {
        if let Some(field) = &$field {
            write_field!($f, $fmt, field);
        }
    };

    // Write out an iterable field.
    ( @all, $f:ident, $fmt:literal, $field:expr ) => {
        for item in &$field {
            write_field!($f, $fmt, item);
        }
    };

    // Write out an optional iterable field.
    ( @optall, $f:ident, $fmt:literal, $field:expr ) => {
        if let Some(field) = &$field {
            for item in field {
                write_field!($f, $fmt, item);
            }
        }
    };
}

/// Write the document out to the provided writer.
pub fn write<W: Write>(mut w: W, doc: &SPDX) -> Result<()> {
    log::info!(target: "cargo_spdx", "writing out file in key-value format");

    write_field!(
        w,
        "SPDXVersion: {}",
        doc.document_creation_information.spdx_version
    );
    write_field!(
        w,
        "DataLicense: {}",
        doc.document_creation_information.data_license
    );
    write_field!(
        w,
        "SPDXID: {}",
        doc.document_creation_information.spdx_identifier
    );
    write_field!(
        w,
        "DocumentName: {}",
        doc.document_creation_information.document_name
    );
    write_field!(
        w,
        "DocumentNamespace: {}",
        doc.document_creation_information.spdx_document_namespace
    );
    //write_field!(@all, w, "ExternalDocumentRef: {}", doc.document_creation_information.external_document_references);
    write_field!(@opt, w, "LicenseListVersion: {}", doc.document_creation_information.creation_info.license_list_version);
    write_field!(@all, w, "Creator: {}", doc.document_creation_information.creation_info.creators);
    write_field!(
        w,
        "Created: {}",
        doc.document_creation_information.creation_info.created
    );
    write_field!(@opt, w, "CreatorComment: {}", doc.document_creation_information.creation_info.creator_comment);
    write_field!(@opt, w, "DocumentComment: {}", doc.document_creation_information.document_comment);

    Ok(())
}
