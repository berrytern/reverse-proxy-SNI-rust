use actix_web::{HttpRequest, HttpResponseBuilder, http::header as actix_web_header, web};
use regex::Regex;
use reqwest::{
    StatusCode,
    header::{HeaderName, HeaderValue},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::{Arc, LazyLock},
};
use std::{
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Policies {
    LogPolicy(LogPolicy),
    ProxyPolicy(ProxyPolicy),
    HeaderPolicy(HeaderPolicy),
    CorsPolicy(CorsPolicy),
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
pub struct ProxyError {
    error: String,
    details: String,
    code: u16,
}
impl From<reqwest::Error> for ProxyError {
    fn from(err: reqwest::Error) -> Self {
        let err = err.without_url();
        ProxyError {
            error: err.to_string(),
            details: err.to_string(),
            code: err.status().unwrap_or(StatusCode::BAD_GATEWAY).into(),
        }
    }
}

impl ProxyPolicy {
    pub async fn run(
        &self,
        req: &HttpRequest,
        url: &str,
        body: reqwest::Body,
        client: &web::Data<reqwest::Client>,
    ) -> Result<reqwest::Response, ProxyError> {
        if let Some(circuit_breaker) = &self.proxy.action.circuit_breaker {
            if !circuit_breaker.proceed() {
                return Err(ProxyError {
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
        let mut forward_req = client.request(method, url).body(body);
        for (key, value) in req.headers() {
            if key != "host" && key != "connection" && key != "content-length" {
                let header_name: HeaderName = key.as_str().parse().unwrap();
                let header_value = HeaderValue::from_str(value.to_str().unwrap())
                    .expect("Failed to convert header value");
                forward_req = forward_req.header(header_name, header_value);
            }
        }
        if let Some(peer_addr) = req.peer_addr() {
            forward_req = forward_req.header("X-Forwarded-For", peer_addr.ip().to_string());
        }

        if let Some(circuit_breaker) = &self.proxy.action.circuit_breaker {
            let response = forward_req.send().await?;
            circuit_breaker.compute(response)
        } else {
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
const REG_REQ_PARAMS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"\$\{([a-z._]+)(?:\[[\'\"]([a-z-]+)[\'\"]\])?\}"#).unwrap());
impl LogPolicy {
    fn extract_params(&self, req: &HttpRequest) -> String {
        let mut new = String::new();
        let mut last_match = 0;
        for caps in REG_REQ_PARAMS.captures_iter(&self.log.action.message) {
            let m = caps.get(0).unwrap();
            new.push_str(&self.log.action.message[last_match..m.start()]);
            match m.as_str() {
                "req.method" => new.push_str(req.method().as_str()),
                "req.path" => new.push_str(req.uri().path()),
                "req.connection.remote_address" => {
                    if let Some(peer_addr) = req.peer_addr() {
                        new.push_str(peer_addr.ip().to_string().as_str())
                    }
                    new.push_str("None")
                }
                "req.client_ip" => {
                    new.push_str(req.connection_info().realip_remote_addr().unwrap_or("None"))
                }
                "req.http_version" => match req.version() {
                    actix_web::http::Version::HTTP_09 => new.push_str("HTTP/0.9"),
                    actix_web::http::Version::HTTP_10 => new.push_str("HTTP/1.0"),
                    actix_web::http::Version::HTTP_11 => new.push_str("HTTP/1.1"),
                    actix_web::http::Version::HTTP_2 => new.push_str("HTTP/2.0"),
                    actix_web::http::Version::HTTP_3 => new.push_str("HTTP/3.0"),
                    _ => new.push_str("None"),
                },
                "req.headers" => {
                    if let Some(header) = caps.get(1) {
                        if let Some(header) = req.headers().get(header.as_str()) {
                            new.push_str(header.to_str().unwrap())
                        } else {
                            new.push_str("None")
                        }
                    } else {
                        new.push_str("None")
                    }
                }
                "original_url" => new.push_str(req.uri().to_string().as_str()),
                value => new.push_str(&format!("${{{value}}}")),
            }
            last_match = m.end();
        }
        new
    }

    pub fn run(&self, req: &HttpRequest) {
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
    pub fn run(&self, req: &mut HttpResponseBuilder) {
        for (key, value) in &self.header.action.headers {
            req.insert_header((key.clone(), value.clone()));
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LogPolicySetup {
    pub condition: Option<Condition>,
    pub action: LogAction,
}
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LogAction {
    pub message: String,
}
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProxyPolicySetup {
    pub condition: Option<Condition>,
    pub action: ProxyAction,
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
    pub max_requests: Option<usize>,
    pub timeout: usize,
    pub error_threshold: Option<usize>,
    #[serde(default)]
    count: Arc<AtomicUsize>,
    #[serde(default)]
    error_count: Arc<AtomicUsize>,
    #[serde(skip, default = "default_last_reset")]
    last_reset: Arc<AtomicU64>,
}
impl CircuitBreaker {
    pub fn proceed(&self) -> bool {
        {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            if now >= self.last_reset.load(Ordering::Relaxed) + self.timeout as u64 {
                self.last_reset.store(now, Ordering::Relaxed);
                self.count.store(0, Ordering::Relaxed);
                self.error_count.store(0, Ordering::Relaxed);
                return true;
            }
        }
        if let Some(max_requests) = self.max_requests {
            if self.count.load(Ordering::Relaxed) >= max_requests {
                return false;
            }
        }
        if let Some(error_threshold) = self.error_threshold {
            if error_threshold <= self.error_count.load(Ordering::Relaxed) {
                return false;
            }
        }
        true
    }
    pub fn compute(&self, response: reqwest::Response) -> Result<reqwest::Response, ProxyError> {
        if response.status().is_server_error() {
            self.error_count.fetch_add(1, Ordering::Relaxed);
        }
        self.count.fetch_add(1, Ordering::Relaxed);
        Ok(response)
    }
}
fn default_last_reset() -> Arc<AtomicU64> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    Arc::new(AtomicU64::new(now))
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HeaderPolicySetup {
    pub condition: Option<Condition>,
    pub action: HeaderAction,
}
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HeaderAction {
    pub headers: HashMap<String, String>,
}
fn default_true() -> bool {
    true
}
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CorsAction {
    pub origin: String,
    pub methods: String,
    pub allowed_headers: String,
}
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CorsPolicySetup {
    pub condition: Option<Condition>,
    pub action: CorsAction,
}
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CorsPolicy {
    #[serde(default = "default_uuid")]
    pub id: String,
    pub cors: CorsPolicySetup,
}
impl CorsPolicy {
    pub fn feed_preflight(&self, req: &HttpRequest, res: &mut HttpResponseBuilder) -> bool {
        if req.method() != actix_web::http::Method::OPTIONS {
            return false;
        }
        if &self.cors.action.origin == "*" {
            res.insert_header((actix_web_header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"));
        } else {
            res.insert_header((
                actix_web_header::ACCESS_CONTROL_ALLOW_ORIGIN,
                self.cors.action.origin.clone(),
            ));
        }
        if &self.cors.action.methods == "*" {
            res.insert_header((actix_web_header::ACCESS_CONTROL_ALLOW_METHODS, "*"));
        } else {
            res.insert_header((
                actix_web_header::ACCESS_CONTROL_ALLOW_METHODS,
                self.cors.action.methods.clone(),
            ));
        }
        if &self.cors.action.allowed_headers == "*" {
            res.insert_header((actix_web_header::ACCESS_CONTROL_ALLOW_HEADERS, "*"));
        } else {
            res.insert_header((
                actix_web_header::ACCESS_CONTROL_ALLOW_HEADERS,
                self.cors.action.allowed_headers.clone(),
            ));
        }
        true
    }
}
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case", tag = "name")]
pub enum Condition {
    PathExact {
        path: String,
    },
    Not {
        #[serde(flatten)]
        condiction: Box<Condition>,
    },
}

impl Condition {
    pub fn proceed(&self, req: &HttpRequest) -> bool {
        match self {
            Condition::PathExact { path } => req.uri().path() == path,
            Condition::Not { condiction } => !condiction.proceed(req),
        }
    }
}
