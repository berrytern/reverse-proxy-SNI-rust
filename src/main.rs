mod config;
mod errors;
mod infrastructure;
use crate::errors::AppError;
use actix_web::{
    App, HttpRequest, HttpResponse, HttpResponseBuilder, HttpServer, http::StatusCode, web,
};
use arc_swap::ArcSwap;
use config::{
    config::{Config, URLType},
    handlers::{HostnameHandler, PathHandler, RequestAction},
};
use futures_util::StreamExt;
use infrastructure::yaml::{
    load_config::load_config,
    load_handlers::{PolicyHandler, register_handlers},
};
use inotify::{Inotify, WatchMask};
use log::{debug, error, info};
use matchit::Router;
use openssl::ssl::{SslAcceptor, SslContext, SslFiletype, SslMethod};
use reqwest::{Client, Response};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::{Arc, LazyLock, RwLock},
};
use tokio::sync::mpsc;

#[derive(Debug, Serialize, Deserialize)]
struct ErrorResponse {
    error: String,
    details: Option<String>,
    code: Option<String>,
}

const DEFAULT_SECURITY_HEADERS: [(&str, &str); 12] = [
    (
        "Content-Security-Policy",
        "default-src 'self';connect-src 'self';base-uri;font-src 'self' https: data:;form-action 'self';frame-ancestors 'self';img-src 'self' data:;object-src 'none';script-src 'self';script-src-attr 'none';style-src 'self' https:;upgrade-insecure-requests",
    ),
    ("Cross-Origin-Resource-Policy", "same-origin"),
    ("Cross-Origin-Opener-Policy", "same-origin"),
    ("Origin-Agent-Cluster", "?1"),
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("X-XSS-Protection", "0"),
    ("Referrer-Policy", "no-referrer"),
    (
        "Strict-Transport-Security",
        "max-age=15552000; includeSubDomains",
    ),
    ("X-DNS-Prefetch-Control", "off"),
    ("X-Download-Options", "noopen"),
    ("X-Permitted-Cross-Domain-Policies", "none"),
];

static CONFIG_PATH: &str = "config.yaml";
static CONFIG: LazyLock<Arc<RwLock<Config>>> = LazyLock::new(|| match load_config(CONFIG_PATH) {
    Ok(config) => Arc::new(RwLock::new(config)),
    Err(err) => {
        panic!("Failed to load config: {err}");
    }
});
static HOST_HANDLERS: LazyLock<Arc<RwLock<HostnameHandler>>> = LazyLock::new(|| {
    let config_guard = CONFIG.read().unwrap();
    let (hostname_handlers, _) = register_handlers(&config_guard);
    debug!("Registered {hostname_handlers:?} host handlers.");
    Arc::new(RwLock::new(hostname_handlers))
});
static PATH_HANDLERS: LazyLock<Arc<RwLock<HashMap<String, PathHandler>>>> = LazyLock::new(|| {
    let config_guard = CONFIG.read().unwrap();
    let (_, path_handlers) = register_handlers(&config_guard);
    debug!("Registered {path_handlers:?} path handlers.");
    Arc::new(RwLock::new(path_handlers))
});

fn add_response_headers(gateway_response: &mut HttpResponseBuilder, response: &Response) {
    for (key, value) in response.headers() {
        match key.as_str() {
            "connection" | "transfer-encoding" | "user-agent" | "server" | "x-powered-by" => {
                continue;
            }
            key => {
                if let Ok(value_str) = value.to_str() {
                    if value_str
                        .bytes()
                        .any(|b| matches!(b, b'\0' | b'\r' | b'\n'))
                    {
                        continue;
                    }
                    gateway_response.insert_header((key, value.to_str().unwrap()));
                }
            }
        }
    }
}
async fn handler_request(
    request_action: &RequestAction,
    req: &HttpRequest,
    mut body: web::Payload,
    client: &web::Data<reqwest::Client>,
) -> HttpResponse {
    let mut gateway_response = HttpResponseBuilder::new(StatusCode::OK);
    let mut gateway_response_body = None;
    for (name, value) in DEFAULT_SECURITY_HEADERS {
        gateway_response.insert_header((name, value));
    }
    let (tx, rx) = mpsc::channel::<Result<web::Bytes, std::io::Error>>(10);
    actix_web::rt::spawn(async move {
        while let Some(chunk) = body.next().await {
            let item = chunk.map_err(std::io::Error::other);
            if tx.send(item).await.is_err() {
                break;
            }
        }
    });
    let stream = futures_util::stream::unfold(rx, |mut receiver| async move {
        receiver.recv().await.map(|item| (item, receiver))
    });

    // 4. Prepare Body Cursor
    let mut body_cursor = Some(reqwest::Body::wrap_stream(stream));
    for policy in &request_action.policies {
        match policy {
            PolicyHandler::Log { policy } => {
                if let Some(condiction) = &policy.log.condition {
                    if !condiction.proceed(req) {
                        continue;
                    }
                }
                policy.run(req);
            }
            PolicyHandler::Proxy {
                policy,
                target,
                count,
                size,
            } => {
                if let Some(condiction) = &policy.proxy.condition {
                    if !condiction.proceed(req) {
                        continue;
                    }
                }

                if let Some(request_body) = body_cursor.take() {
                    match target {
                        URLType::Vec(urls) => {
                            let mut count_value = count.lock().unwrap();
                            let index = *count_value;
                            if urls.len() > 1 {
                                if index < *size {
                                    *count_value += 1;
                                } else {
                                    *count_value = 0;
                                }
                            }
                            drop(count_value);
                            match policy
                                .run(
                                    req,
                                    &format!(
                                        "{}{}",
                                        urls[index as usize].as_str(),
                                        &req.uri().path_and_query().map_or("/", |x| x.as_str())
                                    ),
                                    request_body,
                                    client,
                                )
                                .await
                            {
                                Ok(response) => {
                                    let status_code = actix_web::http::StatusCode::from_u16(
                                        response.status().as_u16(),
                                    )
                                    .unwrap_or(actix_web::http::StatusCode::INTERNAL_SERVER_ERROR);

                                    add_response_headers(&mut gateway_response, &response);
                                    gateway_response.status(status_code);
                                    gateway_response_body = Some(response.bytes_stream());
                                }
                                _ => {
                                    gateway_response
                                        .status(StatusCode::BAD_GATEWAY)
                                        .body("Bad Gateway");
                                }
                            }
                        }
                        URLType::String(url) => {
                            // 4. Convert the Receiver into a Stream that Reqwest accepts
                            if let Ok(response) = policy
                                .run(
                                    req,
                                    &format!(
                                        "{}{}",
                                        &url.to_string(),
                                        &req.uri().path_and_query().map_or("/", |x| x.as_str())
                                    ),
                                    request_body,
                                    client,
                                )
                                .await
                            {
                                let status_code = actix_web::http::StatusCode::from_u16(
                                    response.status().as_u16(),
                                )
                                .unwrap_or(actix_web::http::StatusCode::INTERNAL_SERVER_ERROR);
                                add_response_headers(&mut gateway_response, &response);
                                gateway_response.status(status_code);
                                gateway_response_body = Some(response.bytes_stream());
                            }
                        }
                    }
                }
            }
            PolicyHandler::Header { policy } => {
                if let Some(condiction) = &policy.header.condition {
                    if !condiction.proceed(req) {
                        continue;
                    }
                }
                policy.run(&mut gateway_response);
            }
            PolicyHandler::Cors { policy } => {
                if let Some(condiction) = &policy.cors.condition {
                    if !condiction.proceed(req) {
                        continue;
                    }
                }
                if policy.feed_preflight(req, &mut gateway_response) {
                    return gateway_response.finish();
                }
            }
        }
    }
    if let Some(body) = gateway_response_body {
        gateway_response.streaming(body)
    } else {
        gateway_response
            .status(StatusCode::BAD_GATEWAY)
            .body("Bad Gateway")
    }
}

static SSL_CACHE: LazyLock<Arc<RwLock<HashMap<String, SslContext>>>> = LazyLock::new(|| {
    let config_guard = CONFIG.read().unwrap();
    let cache = build_ssl_cache(&config_guard);
    debug!("Loaded {} SSL contexts", cache.len());
    Arc::new(RwLock::new(cache))
});

fn build_ssl_cache(config: &Config) -> HashMap<String, SslContext> {
    let mut cache = HashMap::new();

    if let Some(https_config) = &config.https {
        for (domain, tls_config) in &https_config.tls {
            let mut context_builder = SslContext::builder(SslMethod::tls()).unwrap();

            // We load the files HERE, not in the callback
            if let Err(e) = context_builder.set_private_key_file(&tls_config.key, SslFiletype::PEM)
            {
                error!("Failed to load key for {domain}: {e}");
                continue;
            }
            if let Err(e) = context_builder.set_certificate_chain_file(&tls_config.cert) {
                error!("Failed to load cert for {domain}: {e}");
                continue;
            }

            cache.insert(domain.clone(), context_builder.build());
        }
    }
    cache
}

pub type RouteTable = Router<PathHandler>;

static DYNAMIC_ROUTER: LazyLock<Arc<ArcSwap<RouteTable>>> =
    LazyLock::new(|| Arc::new(ArcSwap::from_pointee(Router::new())));

fn reload_routes() {
    let mut new_router = Router::new();

    // 1. Iterate your config and build the tree
    // Assuming config.routes is a HashMap<Path, Action>
    if let Ok(path_handlers) = &PATH_HANDLERS.read() {
        for (path, handler) in path_handlers.iter() {
            // matchit supports syntax like "/users/:id"
            if let Err(e) = new_router.insert(path, handler.clone()) {
                error!("Failed to insert route '{path}': {e}");
            }
        }
    }

    // 2. ATOMIC SWAP
    // This is a single CPU instruction pointer change.
    // It is effectively instant. No request is blocked.
    DYNAMIC_ROUTER.store(Arc::new(new_router));

    info!("Routes hot-swapped successfully!");
}

async fn dynamic_router_handler(
    req: HttpRequest,
    body: web::Payload,
    client: web::Data<reqwest::Client>,
) -> HttpResponse {
    let path = req.path();

    let router = DYNAMIC_ROUTER.load();

    // 2. LOOKUP (Radix Tree Match)
    match router.at(path) {
        Ok(match_result) => {
            let path_handler = match_result.value;

            let host: String = req.connection_info().host().to_string();
            let method = req.method().to_string();

            match (path_handler.hosts.get(&host), &path_handler.action) {
                (Some(request_action), _)
                    if request_action.methods.is_empty()
                        || request_action.methods.contains(&method) =>
                {
                    handler_request(request_action, &req, body, &client).await
                }
                (None, Some(request_action))
                    if request_action.methods.is_empty()
                        || request_action.methods.contains(&method) =>
                {
                    handler_request(request_action, &req, body, &client).await
                }
                (_, _) => HttpResponse::Ok().json(ErrorResponse {
                    error: "path not configured".into(),
                    details: None,
                    code: None,
                }),
            }
        }
        Err(_) => {
            // 4. 404 Not Found
            HttpResponse::NotFound().json(ErrorResponse {
                error: "Path not found".into(),
                details: None,
                code: Some("404".into()),
            })
        }
    }
}

#[actix_web::main]
async fn main() -> Result<(), AppError> {
    env_logger::init();
    let file_path = "config.yaml";
    info!("🚀 Gateway starting up...");
    debug!("Loading configuration from {file_path}");
    LazyLock::force(&CONFIG);
    debug!("Registering handlers...");
    LazyLock::force(&HOST_HANDLERS);
    LazyLock::force(&PATH_HANDLERS);
    reload_routes();
    let http_client = Client::builder()
        .redirect(reqwest::redirect::Policy::limited(2))
        .danger_accept_invalid_certs(true)
        .build()
        .expect("couldn't initialize http reqwest client");
    let https_client = http_client.clone();
    let _ = tokio::spawn(async move {
        let inotify = Inotify::init().expect("Failed to initialize inotify");
        match inotify.watches().add(file_path, WatchMask::CLOSE_WRITE) {
            Ok(_) => {
                info!("Watching file: {file_path}");
                let mut buffer = [0; 1024];
                match inotify.into_event_stream(&mut buffer) {
                    Ok(mut stream) => loop {
                        match stream.next().await {
                            Some(Ok(_)) => {
                                match load_config(file_path) {
                                    Ok(new_config) => {
                                        debug!(
                                            "success on load config: {file_path}: {new_config:?}"
                                        );
                                        match CONFIG.try_write() {
                                            Ok(mut config) => {
                                                *config = new_config;
                                                (
                                                    *HOST_HANDLERS.write().unwrap(),
                                                    *PATH_HANDLERS.write().unwrap(),
                                                ) = register_handlers(&config);
                                                reload_routes();
                                                let new_ssl_cache = build_ssl_cache(&config);
                                                match SSL_CACHE.write() {
                                                    Ok(mut cache) => *cache = new_ssl_cache,
                                                    Err(e) => error!(
                                                        "Failed to acquire write lock on SSL_CACHE: {e}"
                                                    ),
                                                }
                                                info!("Configuration and SSL contexts reloaded.");
                                            }
                                            Err(e) => {
                                                error!(
                                                    "Failed to acquire write lock on CONFIG: {e}"
                                                );
                                            }
                                        }
                                    }
                                    Err(err) => {
                                        error!("Failed to load config: {file_path}: {err}");
                                    }
                                };
                            }
                            None => {}
                            Some(Err(error)) => {
                                error!("Failed to read event: {error}");
                            }
                        }
                    },
                    Err(e) => {
                        error!("Failed to read events from inotify stream: {e}");
                    }
                }
            }
            Err(e) => {
                error!("Failed to watch file: {file_path}: {e}");
            }
        };
    });
    if let Ok(config) = CONFIG.read() {
        if let Some(http) = &config.http {
            info!(
                "Starting HTTP server at http://{}:{}",
                http.hostname, http.port
            );
            let _ = HttpServer::new(move || {
                App::new()
                    .app_data(web::Data::new(http_client.clone()))
                    .app_data(web::PayloadConfig::new(10 * 1024 * 1024))
                    .default_service(web::to(
                        |_: HttpRequest, _: web::Bytes, _: web::Data<reqwest::Client>| async move {
                            HttpResponse::NotFound().json(ErrorResponse {
                                error: "Domain not configured".into(),
                                details: None,
                                code: None,
                            })
                        },
                    ))
            })
            .bind((http.hostname.clone(), http.port))?
            .run();
        }
    }
    if let Ok(config) = CONFIG.read() {
        if let Some(https) = config.https.clone() {
            drop(config);
            let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
            debug!("Configuring SNI for HTTPS server.");
            // Set SNI callback
            builder.set_servername_callback(move |ssl, _| {
                if let Ok(cache) = SSL_CACHE.read() {
                    let server_name = ssl.servername(openssl::ssl::NameType::HOST_NAME);

                    // 1. Try to find the specific domain
                    if let Some(name) = server_name {
                        if let Some(context) = cache.get(name) {
                            // This is fast (Arc clone internally in OpenSSL)
                            ssl.set_ssl_context(context).unwrap();
                            return Ok(());
                        }
                    }

                    // 2. Fallback to "default"
                    if let Some(context) = cache.get("default") {
                        ssl.set_ssl_context(context).unwrap();
                        return Ok(());
                    }
                }
                Ok(())
            });
            info!(
                "Starting HTTPS server at https://{}:{}",
                https.hostname, https.port
            );
            HttpServer::new(move || {
                let mut app = App::new();
                app = app
                    .app_data(web::Data::new(https_client.clone()))
                    .app_data(web::PayloadConfig::new(10 * 1024 * 1024));

                app.default_service(web::to(dynamic_router_handler))
            })
            .bind_openssl((https.hostname.clone(), https.port), builder)?
            .run()
            .await?;
        }
    }
    Ok(())
}
