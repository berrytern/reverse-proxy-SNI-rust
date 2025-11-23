use crate::config;
use crate::errors::AppError;
use config::config::Config;
use log::error;
use regex::Regex;
use std::sync::LazyLock;
use std::{env, io::Read};

const REG1: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\$\{([a-zA-Z_][0-9a-zA-Z_]*)(:-([^}]+))?\}").unwrap());

fn expand_var(raw_config: &mut String) -> Result<(), AppError> {
    let mut new = String::new();
    let mut last_match = 0;
    for caps in REG1.captures_iter(raw_config) {
        let m = caps.get(0).unwrap();
        new.push_str(&raw_config[last_match..m.start()]);

        let default = caps.get(3);
        let env_name = caps.get(1).unwrap().as_str();
        match env::var(env_name) {
            Ok(val) => {
                new.push_str(&val);
            }
            Err(_) => {
                if let Some(default) = default {
                    new.push_str(default.as_str());
                } else {
                    error!("Cannot find environment variable: {env_name}");
                    return Err(AppError {
                        message: format!("Cannot find environment variable: {env_name}"),
                    });
                }
            }
        }
        last_match = m.end();
    }
    new.push_str(&raw_config[last_match..]);
    *raw_config = new;
    Ok(())
}

fn validate_https(config: &Config, errors: &mut Vec<String>) {
    match (&config.http, &config.https) {
        (None, None) => {
            errors.push("Invalid gateway configuration: http or https must be defined".into());
        }
        (_, Some(https)) => {
            if https.tls.is_empty() {
                errors.push("Invalid HTTPS configuration: need to setup tls field properly".into());
            }
        }
        (_, _) => {}
    }
}

pub fn load_config(file_path: &str) -> Result<Config, AppError> {
    match std::fs::File::open(file_path) {
        Ok(mut f) => {
            let mut data = String::new();
            if f.read_to_string(&mut data).is_err() {
                error!("Cannot read config file");
                return Err(AppError {
                    message: "Cannot read config file".into(),
                });
            }
            expand_var(&mut data)?;
            match serde_yaml::from_str(&data) {
                Ok(fc) => {
                    let mut errors: Vec<String> = vec![];
                    validate_https(&fc, &mut errors);
                    if !errors.is_empty() {
                        error!("Errors found in configuration file:");
                        for error in errors {
                            error!("{error}");
                        }
                        return Err(AppError {
                            message: "Invalid configuration".into(),
                        });
                    }
                    Ok(fc)
                }
                Err(err) => {
                    error!("Invalid YAML or cannot be converted to Config.{err}");
                    Err(err.into())
                }
            }
        }
        Err(err) => {
            error!("Cannot open file: {err}");
            Err(err.into())
        }
    }
}
