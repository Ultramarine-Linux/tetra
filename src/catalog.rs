//! Recipe catalog and rendering engine.
//!
//! Re-exported from the `tetra-recipe` crate (`crates/tetra-recipe`), which
//! owns the recipe schema, validation, bundle digest and image policy. The
//! only part kept here is writing rendered files to disk, which needs the
//! agent's confined file writer.

pub use tetra_recipe::*;

use crate::prelude::*;

/// Tetra's file-backed render step: [`RenderOptions::render`] plus writing the
/// result under `output_dir`.
pub trait WriteRendered: Sized {
    /// Full file-backed pipeline: load recipe + values, render all resources, and
    /// optionally write them to `output_dir`.
    ///
    /// This is the entry point used by the CLI `render` command. Disk writes are
    /// skipped on `dry_run` or when `output_dir` is `None`, but the rendered
    /// resources are always returned so the caller can preview them.
    fn from_files(options: &RenderOptions) -> Result<Vec<Self>>;
}

impl WriteRendered for RenderedResource {
    fn from_files(options: &RenderOptions) -> Result<Vec<Self>> {
        let rendered = options.render()?;

        // Only touch the filesystem when explicitly asked to: dry-run previews and
        // agent calls that just want the rendered bytes both rely on this skip.
        if let Some(output_dir) = &options.output_dir
            && !options.dry_run
        {
            fs::create_dir_all(output_dir).with_context(|| {
                format!(
                    "failed to create output directory `{}`",
                    output_dir.display()
                )
            })?;
            // Rendered filenames come from the recipe: keep them inside
            // `output_dir`.
            for resource in &rendered {
                crate::agent::module_support::write_under(
                    output_dir,
                    &resource.filename,
                    resource.contents.as_bytes(),
                    resource.kind.mode(),
                    false,
                )?;
            }
        }

        Ok(rendered)
    }
}
