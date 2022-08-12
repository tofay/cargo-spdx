//! Handle outputting the document to the user.

use crate::{format, Format};
use anyhow::{anyhow, Result};
use spdx_rs::models::SPDX;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::ops::Not as _;
use std::path::{Path, PathBuf};

/// Handles writing to the correct path.
#[derive(Debug)]
pub struct OutputManager {
    /// The path to be written to.
    pub to: PathBuf,
    /// The format to write the output in.
    format: Format,
    /// Whether output is being forced.
    force: bool,
}

impl OutputManager {
    /// Get a new output manager based on CLI args and package info.
    pub fn new(path: &Path, force: bool, format: Format) -> Self {
        let to = path.to_owned();
        OutputManager { to, format, force }
    }

    /// Write the document to the output file in the specified format.
    #[inline]
    pub fn write_document(&self, doc: &SPDX) -> Result<()> {
        // Check the output file has a file name and isn't a directory.
        if self.to.file_name().is_none() {
            return Err(anyhow!("missing output file name"));
        }

        if self.to.is_dir() {
            return Err(anyhow!("output can't be a directory"));
        }

        // Get the writer to the output file.
        let mut writer = self.get_writer()?;

        // Write the document out in the requested format.
        match self.format {
            Format::KeyValue => Ok(format::key_value::write(&mut writer, doc)?),
            Format::Json => Ok(serde_json::to_writer_pretty(writer, doc)?),
            Format::Yaml => Ok(serde_yaml::to_writer(writer, doc)?),
            Format::Rdf => Err(anyhow!("{} format not yet implemented", self.format)),
        }
    }

    /// Get a writer to the output file.
    ///
    /// Returns an error if the output file already exists and the user hasn't set output
    /// to be forced.
    fn get_writer(&self) -> Result<Box<dyn Write>> {
        // A little truth table making clear this conditional is the right one.
        //
        // ---------
        // | T | T | - forcing and exists - no error
        // | T | F | - forcing and doesn't exist - no error
        // | F | T | - not forcing and exists - error
        // | F | F | - not forcing and doesn't exist - no error
        // ---------
        if self.force.not() && self.to.exists() {
            return Err(anyhow!("output file already exists: {}", self.to.display()));
        }

        Ok(Box::new(BufWriter::new(File::create(&self.to)?)))
    }
}
