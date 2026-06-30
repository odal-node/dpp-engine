//! Interactive console (the bare `odal` TUI): menu, forms, and guided setup.

mod file_picker;
pub(crate) mod forms;
mod menu;
pub(crate) mod setup;
mod validators;

pub async fn run() -> anyhow::Result<()> {
    menu::event_loop().await
}
