//! Handlebars rendering. Built-in templates ship with the crate.
//! A `templates_dir` file of the same name replaces one template.

use std::fs;
use std::path::Path;

use crate::Error;

pub(crate) const ABUSE_EMAIL: &str = include_str!("../../templates/abuse-email.hbs");
pub(crate) const EVIDENCE: &str = include_str!("../../templates/evidence.md.hbs");

pub(crate) fn load_template(
    dir: Option<&Path>,
    name: &str,
    fallback: &str,
) -> Result<String, Error> {
    let Some(dir) = dir else {
        return Ok(fallback.to_string());
    };
    let path = dir.join(name);
    if !path.is_file() {
        return Ok(fallback.to_string());
    }
    fs::read_to_string(&path).map_err(|err| Error::Config(format!("{}: {err}", path.display())))
}

pub(crate) fn render_template(
    source: &str,
    data: &impl serde::Serialize,
) -> Result<String, String> {
    let mut engine = handlebars::Handlebars::new();
    engine
        .register_template_string("report", source)
        .map_err(|err| err.to_string())?;
    engine.render("report", data).map_err(|err| err.to_string())
}
