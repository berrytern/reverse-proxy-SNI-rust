use actix_web::{http, web, App, HttpRequest, HttpResponse, HttpServer};
use actix_cors::Cors;
use reqwest::header::{
    HeaderName as ReqwestHeaderName,
    HeaderValue as ReqwestHeaderValue
};
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod, SslContext};
use serde::{Serialize, Deserialize};
use std::{collections::HashMap,sync::OnceLock};
use reqwest::Client;
use std::fs;
use log::error;
use env_logger;

#[derive(Clone, Debug, Deserialize)]
struct DomainConfig {
    target: String,
    ssl: SslConfig,
}

#[derive(Clone, Debug, Deserialize)]
struct SslConfig {
    key_path: String,
    cert_path: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ErrorResponse {
    error: String,
    details: Option<String>,
    code: Option<String>,
}

async fn forward_request(
    req: HttpRequest,
    body: web::Bytes,
    target_url: String,
    client: web::Data<reqwest::Client>,
) -> Result<HttpResponse, actix_web::Error> {
    let url = format!("{}{}", target_url, req.uri().path_and_query().map_or("", |x| x.as_str()));
    
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
    let mut forward_req = client
        .request(method, &url)
        .body(body.to_vec());

    for (key, value) in req.headers() {
        if key != "host" && key != "connection" && key != "content-length" {
            let header_name: ReqwestHeaderName = key.as_str().parse().unwrap();
            let header_value: ReqwestHeaderValue = ReqwestHeaderValue::from_str(value.to_str().unwrap())
            .expect("Failed to convert header value");
            forward_req = forward_req.header(header_name, header_value);
        }
    }
    if let Some(peer_addr) = req.peer_addr(){
        forward_req = forward_req.header("X-Forwarded-For", peer_addr.ip().to_string());
    }

    match forward_req.send().await {
        Ok(response) => {
            let status_code = actix_web::http::StatusCode::from_u16(response.status().as_u16())
            .unwrap_or(actix_web::http::StatusCode::INTERNAL_SERVER_ERROR);
            let mut builder = HttpResponse::build(status_code);
            
            for (key, value) in response.headers() {
                match key.as_str() {
                    "connection" | "transfer-encoding" | "user-agent" | "server" | "x-powered-by" => {
                        continue;
                    }
                    key => {
                        if let Ok(value_str) = value.to_str() {
                            if value_str.bytes().any(|b| matches!(b, b'\0' | b'\r' | b'\n')){
                                error!("Discarding invalid header: {} => {:?}", key, value);
                                continue;
                            }
                            builder.append_header((key, value.to_str().unwrap()));
                        }
                    }
                }
            }

            let body_bytes = response.bytes_stream();
            builder.insert_header(("Content-Security-Policy", "default-src 'self';base-uri 'self';font-src 'self' https: data:;form-action 'self';frame-ancestors 'self';img-src 'self' data:;object-src 'none';script-src 'self' 'unsafe-inline' 'unsafe-eval';script-src-attr 'none';style-src 'self' https: 'unsafe-inline';upgrade-insecure-requests"))
                .insert_header(("Cross-Origin-Resource-Policy", "same-origin"))
                .insert_header(("Cross-Origin-Opener-Policy", "same-origin"))
                .insert_header(("Origin-Agent-Cluster", "?1"))
                .insert_header(("X-Content-Type-Options", "nosniff"))
                .insert_header(("X-Frame-Options", "DENY"))
                .insert_header(("X-XSS-Protection", "0"))
                .insert_header(("Referrer-Policy", "no-referrer"))
                .insert_header(("Strict-Transport-Security", "max-age=15552000; includeSubDomains"))
                .insert_header(("X-DNS-Prefetch-Control", "off"))
                .insert_header(("X-Download-Options", "noopen"))
                .insert_header(("X-Permitted-Cross-Domain-Policies", "none"));
            Ok(builder.streaming(body_bytes))
        }
        Err(e) => {
            error!("Forward request error: {}", e);
            let error_response = ErrorResponse {
                error: "Proxy Internal Error".into(),
                details: Some(e.to_string()),
                code: Some("proxy_error".into()),
            };
            Ok(HttpResponse::InternalServerError().json(error_response))
        }
    }
}

static DOMAIN_ROUTES: OnceLock<HashMap<String, DomainConfig>> = OnceLock::new();

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    let config_content: String = fs::read_to_string("config.json")?;
    DOMAIN_ROUTES.set(match serde_json::from_str(&config_content) {
        Ok(routes) => routes,
        Err(err) => {
            error!("Failed to parse config.json: {}", err);
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid JSON format in config.json"));
        }
    }).expect("Failed to set domain routes");
    let default_ssl_config = SslConfig {
        key_path: "/etc/ssl/api1.nutespb.com.br/privkey.pem".into(),
        cert_path: "/etc/ssl/api1.nutespb.com.br/fullchain.pem".into(),
    };

    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    builder.set_private_key_file(&default_ssl_config.key_path, SslFiletype::PEM).unwrap();
    builder.set_certificate_chain_file(&default_ssl_config.cert_path).unwrap();
    // Set SNI callback
    builder.set_servername_callback(move |ssl, _| {
        if let Some(server_name) = ssl.servername(openssl::ssl::NameType::HOST_NAME){
            if let Some(config) = DOMAIN_ROUTES.get().unwrap().get(server_name) {
    
                let mut context = SslContext::builder(SslMethod::tls()).unwrap();
                context.set_private_key_file(&config.ssl.key_path, SslFiletype::PEM).unwrap();
                context.set_certificate_chain_file(&config.ssl.cert_path).unwrap();
    
                ssl.set_ssl_context(&context.build()).unwrap();
            }
        }

        Ok(())
    });

    let client = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .danger_accept_invalid_certs(true).build().expect("couldn't initialize http reqwest client");

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(client.clone()))
            .app_data(web::PayloadConfig::new(10 * 1024 * 1024))
            .default_service(web::to(
                |req: HttpRequest, body: web::Bytes, client: web::Data<reqwest::Client>| 
                async move {
                
                    let host = req.connection_info().host().to_string();
                    
                    if let Some(config) = DOMAIN_ROUTES.get().unwrap().get(&host) {
                        forward_request(req, body, config.target.clone(), client).await
                    } else {
                        Ok(HttpResponse::NotFound().json(ErrorResponse {
                            error: "Domain not configured".into(),
                            details: None,
                            code: None,
                        }))
                    }
                }
            ))
    })
    .bind_openssl("0.0.0.0:443", builder)?
    .run()
    .await
}