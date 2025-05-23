use std::{collections::HashMap, sync::{Arc, Mutex, LazyLock}, time::Duration};
use actix_web::{web, HttpRequest, HttpResponseBuilder};
use regex::Regex;
use reqwest::{header::{HeaderName, HeaderValue}, StatusCode};
use serde::{Serialize, Deserialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Policies {
    LogPolicy(LogPolicy),
    ProxyPolicy(ProxyPolicy),
    HeaderPolicy(HeaderPolicy),
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
pub struct ProxyError{
    error: String,
    details: String,
    code: u16,

}
impl From<reqwest::Error> for ProxyError {
    fn from(err: reqwest::Error) -> Self {
        let err = err.without_url();
        ProxyError{
            error: err.to_string(),
            details: err.to_string(),
            code: err.status().unwrap_or(StatusCode::BAD_GATEWAY).into(),
        }
    }
}

impl ProxyPolicy {
    pub async fn run(
        &self, req: &HttpRequest, url: &str, body: Vec<u8>, client: &web::Data<reqwest::Client>
    ) -> Result<reqwest::Response, ProxyError>{
        
        if let Some(circuit_breaker) = &self.proxy.action.circuit_breaker {
            if !circuit_breaker.proceed(){
                return Err(ProxyError{
                    error: "Circuit Breaker".to_string(),
                    details: "Circuit Breaker".to_string(),
                    code: StatusCode::SERVICE_UNAVAILABLE.into(),
                });
            }
        }
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
        
        if let Some(circuit_breaker) = &self.proxy.action.circuit_breaker {
            let response = forward_req.send().await?;
            circuit_breaker.compute(response)
        } else{
            forward_req.send().await.map_err(|err| err.into())
        } 
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
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HeaderPolicy {
    #[serde(default = "default_uuid")]
    pub id: String,
    pub header: HeaderPolicySetup,
}
impl HeaderPolicy {
    pub fn run(
        &self, req: &mut HttpResponseBuilder
    ) -> () {
        for (key, value) in &self.header.action.headers {
            req.insert_header((key.clone(), value.clone()));
        }
    }
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
    pub circuit_breaker: Option<CircuitBreaker>,
    pub service_endpoint: String,
}
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CircuitBreaker {
    pub max_requests: Option<i32>,
    pub timeout: i32,
    pub error_threshold: Option<i32>,
    #[serde(default)]
    count: Arc<Mutex<i32>>,
    #[serde(default)]
    error_count: Arc<Mutex<i32>>,
    #[serde(default)]
    elapsed_time: Arc<Mutex<Duration>>,
}
impl CircuitBreaker {
    pub fn proceed(&self) -> bool {
        {
            let mut elapsed_time = self.elapsed_time.lock().unwrap();
            if elapsed_time.as_secs() > self.timeout as u64 {
                *elapsed_time = Duration::new(0, 0);
                *self.count.lock().unwrap() = 0;
                *self.error_count.lock().unwrap() = 0;
                return true;
            }
        }
        if let Some(max_requests) = self.max_requests {
            {
                if *self.count.lock().unwrap() >= max_requests {
                    return false;
                }
            }
        }
        if let Some(error_threshold) = self.error_threshold {
            {
                if error_threshold <= *self.error_count.lock().unwrap() {
                    return false;
                }
            }
        }
        true
    }
    pub fn compute(&self, response: reqwest::Response) -> Result<reqwest::Response, ProxyError> {
        if response.status().is_server_error() {
            {
                if let Ok(mut error_count) = self.error_count.lock(){
                    *error_count+=1;
                }
            }
        }
        *self.count.lock().unwrap()+=1;
        Ok(response)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HeaderPolicySetup {
    pub condition: Option<Condition>,
    pub action: HeaderAction
}
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HeaderAction {
    pub headers: HashMap<String, String>,
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
    pub fn proceed(&self, req: &HttpRequest) -> bool {
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