use std::collections::HashMap;
use serde::{Serialize, Deserialize};

use super::policies::Policies;

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub http: Option<Http>,
    pub https: Option<Https>,
    pub api_endpoints: HashMap<String, EndpointType>,
    pub service_endpoints: HashMap<String, Service>,
    pub policies: Vec<String>,
    pub pipelines: HashMap<String, Pipelines>
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Http {
    pub port: u16,
    pub hostname: String,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct Https {
    pub port: u16,
    pub hostname: String,
    pub tls: HashMap<String, Tls>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Tls {
    pub key: String,
    pub cert: String
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct Endpoint{
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_path")]
    pub paths: PathType,
    pub methods: Option<Vec<String>>,
}

fn default_host() -> String {
    "*".to_string()
}
fn default_path() -> PathType {
    PathType::String("*".to_string())
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Service {
    pub url: URLType,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Pipelines {
    pub api_endpoints: Vec<String>,
    pub policies: Vec<Policies>
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EndpointType {
    Endpoint(Endpoint),
    VecEndpoint(Vec<Endpoint>)
}
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PathType {
    String(String),
    Vec(Vec<String>)
}
#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum URLType {
    String(String),
    Vec(Vec<String>)
}
