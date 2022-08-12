//! Generate an SPDX SBOM for a Rust crate.

#![deny(missing_debug_implementations)]
#![deny(missing_copy_implementations)]
#![deny(missing_docs)]

use crate::cargo::MetadataExt;
use crate::cli::Args;
use crate::format::Format;
use crate::output::OutputManager;
use anyhow::Result;
use build::build;
use cargo_metadata::MetadataCommand;
use clap::Parser;
use document::get_creation_info;
use spdx_rs::models::{DocumentCreationInformation, SPDX};
use std::path::PathBuf;

mod build;
mod cargo;
mod cli;
mod document;
mod format;
mod git;
mod output;

/// Program entrypoint, only inits the system, calls `run` and reports errors.
fn main() -> Result<()> {
    // Start the environment logger.
    env_logger::init();
    let args = Args::parse();

    // Invoke build subcommand if specified to run `cargo build` with added SBOMs
    if let Some(cmd) = &args.subcommand {
        match cmd {
            cli::Command::Build { args: build_args } => {
                build(build_args, args.host_url()?.as_ref(), args.format())?;
            }
        };
    }
    // Otherwise create an SBOM for the current workspace
    else {
        // Figure out where the SPDX file will be written, setting up a manager to ensure we only write when conditions are met.
        let output_manager = if let Some(output) = args.output() {
            // User specified a path, use that
            OutputManager::new(output, args.force(), args.format())
        } else {
            // Determine path from metadata
            let metadata = MetadataCommand::new().exec()?;
            let path = PathBuf::from(format!(
                "{}{}",
                &metadata.root()?.name,
                args.format().extension()
            ));
            OutputManager::new(&path, args.force(), args.format())
        };

        let document_creation_information = DocumentCreationInformation {
            document_name: output_manager
                .to
                .file_name()
                .unwrap()
                .to_string_lossy()
                .to_string(),
            creation_info: get_creation_info()?,
            spdx_document_namespace: args.host_url()?.to_string(),
            ..Default::default()
        };

        let doc = SPDX {
            document_creation_information,
            package_information: Vec::new(),
            other_licensing_information_detected: Vec::new(),
            file_information: Vec::new(),
            snippet_information: Vec::new(),
            relationships: Vec::new(),
            annotations: Vec::new(),
            spdx_ref_counter: 0,
        };
        output_manager.write_document(&doc)?;
    }
    Ok(())
}
