use std::{collections::HashMap, sync::LazyLock};
use actix_web::{web, HttpRequest};
use regex::Regex;
use reqwest::header::{HeaderName, HeaderValue};
use serde::{Serialize, Deserialize};
use uuid::Uuid;


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
#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Policies {
    LogPolicy(LogPolicy),
    ProxyPolicy(ProxyPolicy)
}
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProxyPolicy {
    #[serde(default = "default_uuid")]
    pub id: String,
    pub proxy: ProxyPolicySetup,
}
fn default_uuid() -> String {
    Uuid::new_v4().to_string()
}
impl ProxyPolicy {
    pub async fn run(
        &self, req: &HttpRequest, url: &str, body: Vec<u8>, client: &web::Data<reqwest::Client>
    ) -> Result<reqwest::Response, reqwest::Error>{
        let method = match req.method().as_str() {
            "GET" => reqwest::Method::GET,
            "POST" => reqwest::Method::POST,
            "PUT" => reqwest::Method::PUT,
            "DELETE" => reqwest::Method::DELETE,
            "HEAD" => reqwest::Method::HEAD,
            "OPTIONS" => reqwest::Method::OPTIONS,
            "CONNECT" => reqwest::Method::CONNECT,
            "PATCH" => reqwest::Method::PATCH,
            "TRACE" => reqwest::Method::TRACE,
            _ => reqwest::Method::GET,
        };
        let mut forward_req = client.request(method, url)
        .body(body);
        for (key, value) in req.headers() {
            if key != "host" && key != "connection" && key != "content-length" {
                let header_name: HeaderName = key.as_str().parse().unwrap();
                let header_value= HeaderValue::from_str(value.to_str().unwrap())
                .expect("Failed to convert header value");
                forward_req = forward_req.header(header_name, header_value);
            }
        }
        if let Some(peer_addr) = req.peer_addr(){
            forward_req = forward_req.header("X-Forwarded-For", peer_addr.ip().to_string());
        }
        forward_req.send().await
    }
}
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LogPolicy {
    #[serde(default = "default_uuid")]
    pub id: String,
    pub log: LogPolicySetup,
}
const REG_REQ_PARAMS: LazyLock<Regex> = LazyLock::new(||Regex::new(r#"\$\{([a-z._]+)(?:\[[\'\"]([a-z-]+)[\'\"]\])?\}"#).unwrap());
impl LogPolicy {

    fn extract_params(&self, req: &HttpRequest) -> String {
        let mut new = String::new();
        let mut last_match = 0;
        for caps in REG_REQ_PARAMS.captures_iter(&self.log.action.message).into_iter() {
            let m = caps.get(0).unwrap();
            new.push_str(&self.log.action.message[last_match..m.start()]);
            match m.as_str() {
                "req.method" => new.push_str(req.method().as_str()),
                "req.path" => new.push_str(req.uri().path()),
                "req.connection.remote_address" => {
                    if let Some(peer_addr) = req.peer_addr(){
                        new.push_str(peer_addr.ip().to_string().as_str())
                    }
                    new.push_str("None")
                },
                "req.client_ip" => {
                    new.push_str(req.connection_info().realip_remote_addr().unwrap_or("None"))
                },
                "req.http_version" => {
                    match req.version(){
                        actix_web::http::Version::HTTP_09 => {new.push_str("HTTP/0.9")},
                        actix_web::http::Version::HTTP_10 => {new.push_str("HTTP/1.0")},
                        actix_web::http::Version::HTTP_11 => {new.push_str("HTTP/1.1")},
                        actix_web::http::Version::HTTP_2 => {new.push_str("HTTP/2.0")},
                        actix_web::http::Version::HTTP_3 => {new.push_str("HTTP/3.0")},
                        _ => {new.push_str("None")}
                    }
                },
                "req.headers" => {
                    if let Some(header) = caps.get(1){
                        if let Some(header) = req.headers().get(header.as_str()){
                            new.push_str(header.to_str().unwrap())
                        } else {
                            new.push_str("None")
                        }
                    } else {
                        new.push_str("None")
                    }
                    
                },
                "original_url" => new.push_str(req.uri().to_string().as_str()),
                value => new.push_str(&format!("${{{}}}", value))
            }
            last_match = m.end();
        };
        new
    }

    pub fn run(
        &self, req: &HttpRequest
    ) -> () {

        log::info!("{}", self.extract_params(req));
    }
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

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LogPolicySetup {
    pub condition: Option<Condition>,
    pub action: LogAction
}
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LogAction{
    pub message: String,
}
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProxyPolicySetup {
    pub condition: Option<Condition>,
    pub action: ProxyAction
}
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProxyAction {
    #[serde(default = "default_true")]
    pub change_origin: bool,
    #[serde(default = "default_true")]
    pub secure: bool,
    pub timeout: Option<i32>,
    pub service_endpoint: String,
}
fn default_true() -> bool {
    true
}
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case", tag = "name")]
pub enum Condition {
    PathExact { path: String },
    Not {
        #[serde(flatten)] 
        condiction: Box<Condition>,
    }
}


impl Condition {
    pub fn proceed(&self, req: HttpRequest) -> bool {
        match self {
            Condition::PathExact { path } => {
                req.uri().path() == path
            }
            Condition::Not { condiction } => {
                !condiction.proceed(req)
            }
        }
    }
}


