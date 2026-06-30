//! `odal import` — bulk-import passports from a CSV/XLSX file.

use anyhow::Result;
use indicatif::{ProgressBar, ProgressStyle};

use crate::{
    config::Config,
    core::{
        passport::action_import,
        types::{ImportParams, ProgressEvent},
    },
    http::OdalClient,
    stateless::render::render_import_result,
};

pub async fn run_import(file: &str) -> Result<()> {
    let cfg = Config::load()?;
    let client = OdalClient::new(&cfg.api_key);
    let params = ImportParams {
        file: file.to_owned(),
    };

    let pb = ProgressBar::new(0);
    pb.set_style(
        ProgressStyle::with_template(
            "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})",
        )
        .unwrap()
        .progress_chars("=>-"),
    );
    let pb2 = pb.clone();
    let progress = move |evt: ProgressEvent| match evt {
        ProgressEvent::Started { total } => {
            if let Some(t) = total {
                pb2.set_length(t);
            }
        }
        ProgressEvent::Tick { current } => pb2.set_position(current),
        ProgressEvent::Done => pb2.finish_and_clear(),
    };

    let result = action_import(&params, &client, &cfg, Some(&progress)).await?;
    render_import_result(&result, file);

    if result.failed > 0 {
        anyhow::bail!("{} records failed to import", result.failed);
    }
    Ok(())
}
