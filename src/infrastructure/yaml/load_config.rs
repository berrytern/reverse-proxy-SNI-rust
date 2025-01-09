use std::sync::LazyLock;
use std::{env, io::Read, process::exit};
use regex::Regex;
use config::config::Config;

use crate::config;

const REG1: LazyLock<Regex> = LazyLock::new(||Regex::new(r"\$\{([a-zA-Z_][0-9a-zA-Z_]*)(:-([^}]+))?\}").unwrap());

fn expand_var(raw_config: &mut String){
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
            },
            Err(_) => {
                if let Some(default) = default {
                    new.push_str(default.as_str());
                } else {
                    println!("Cannot find environment variable: {}", env_name);
                    exit(0)
                }
            }
        }
        last_match = m.end();
    }
    new.push_str(&raw_config[last_match..]);
    *raw_config = new;
}

fn validate_https(config: &Config, errors: &mut Vec<String>){
    match (&config.http, &config.https) {
        (None, None) => {
            errors.push("Invalid gateway configuration: http or https must be defined".into());
        },
        (_, Some(https)) => {
            if https.tls.get("default").is_none() {
                errors.push("Invalid HTTPS configuration: default field is required in https.tls".into());
            }
        },
        (_,_) => {}
    }
}

pub fn load_config(file_path: &str) -> Config {
    match std::fs::File::open(file_path){
        Ok(mut f) => {
            let mut data = String::new();
            if f.read_to_string(&mut data).is_err(){
                println!("Cannot read config file");
                exit(0);
            }
            expand_var(&mut data);
            return match serde_yaml::from_str(&data) {
                Ok(fc) => {
                    let mut errors: Vec<String> = vec![];
                    validate_https(&fc, &mut errors);
                    if errors.len() > 0 {
                        println!("Errors found in configuration file:");
                        for error in errors {
                            println!("{}", error);
                        }
                        exit(0);
                    }
                    fc
                },
                Err(err) => {
                    println!("Invalid YAML or cannot be converted to Config.{}", err);
                    exit(0);
                }
            };
        },
            Err(err) => {
            println!("Cannot open file: {}", err);
            exit(0);
        }

    }
    
}