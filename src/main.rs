mod config;
mod infrastructure;
use config::{config::{Config, URLType}, handlers::{HostnameHandler, PathHandler, RequestAction}};
use infrastructure::yaml::{load_config::load_config, load_handlers::{register_handlers, PolicyHandler}};
use actix_web::{http::StatusCode, web, App, HttpRequest, HttpResponse, HttpResponseBuilder, HttpServer};
use openssl::ssl::{SslAcceptor, SslContext, SslFiletype, SslMethod};
use serde::{Serialize, Deserialize};
use std::{collections::HashMap, sync::OnceLock};
use reqwest::{Client, Response};
use env_logger;

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

const DEFAULT_SECURITY_HEADERS: [(&'static str,&'static str); 12] = [
    ("Content-Security-Policy", "default-src 'self';connect-src 'self';base-uri;font-src 'self' https: data:;form-action 'self';frame-ancestors 'self';img-src 'self' data:;object-src 'none';script-src 'self';script-src-attr 'none';style-src 'self' https:;upgrade-insecure-requests"),
    ("Cross-Origin-Resource-Policy", "same-origin"),
    ("Cross-Origin-Opener-Policy", "same-origin"),
    ("Origin-Agent-Cluster", "?1"),
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("X-XSS-Protection", "0"),
    ("Referrer-Policy", "no-referrer"),
    ("Strict-Transport-Security", "max-age=15552000; includeSubDomains"),
    ("X-DNS-Prefetch-Control", "off"),
    ("X-Download-Options", "noopen"),
    ("X-Permitted-Cross-Domain-Policies", "none"),
];

static CONFIG: OnceLock<Config> = OnceLock::new();
static HOST_HANDLERS: OnceLock<HostnameHandler> = OnceLock::new();
static PATH_HANDLERS: OnceLock<HashMap<String, PathHandler>> = OnceLock::new();

fn add_response_headers(gateway_response: &mut HttpResponseBuilder, response: &Response){
    for (key, value) in response.headers() {
        match key.as_str() {
            "connection" | "transfer-encoding" | "user-agent" | "server" | "x-powered-by" => {
                continue;
            }
            key => {
                if let Ok(value_str) = value.to_str() {
                    if value_str.bytes().any(|b| matches!(b, b'\0' | b'\r' | b'\n')){
                        continue;
                    }
                    gateway_response.insert_header((key, value.to_str().unwrap()));
                }
            }
        }
    }
}
async fn handler_request(request_action: &RequestAction, req: &HttpRequest, body: web::Bytes, client: &web::Data<reqwest::Client>) -> HttpResponse {
    let mut gateway_response = HttpResponseBuilder::new(StatusCode::OK);
    let mut gateway_response_body = None;
    for (name, value) in DEFAULT_SECURITY_HEADERS {
        gateway_response.insert_header((name, value));
    }
    for policy in &request_action.policies {
        match policy {
            PolicyHandler::Log { policy } => {
                policy.run(&req);
            },
            PolicyHandler::Proxy { policy, target, count, size } => {
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
                        if let Ok(response) = policy.run(&req, &format!("{}{}", urls[index as usize].as_str(), &req.uri().path_and_query().map_or("/", |x| x.as_str())), body.to_vec(), &client).await{
                            let status_code = actix_web::http::StatusCode::from_u16(response.status().as_u16())
                            .unwrap_or(actix_web::http::StatusCode::INTERNAL_SERVER_ERROR);
                            
                            add_response_headers(&mut gateway_response, &response);
                            gateway_response.status(status_code);
                            gateway_response_body = Some(response.bytes_stream());
                        } else {
                            gateway_response.status(StatusCode::BAD_GATEWAY).body("Bad Gateway");
                        }
                    },
                    URLType::String(url) => {
                        if let Ok(response) = policy.run(&req, &format!("{}{}", &url.to_string(), &req.uri().path_and_query().map_or("/", |x| x.as_str())), body.to_vec(), &client).await{
                            let status_code = actix_web::http::StatusCode::from_u16(response.status().as_u16())
                            .unwrap_or(actix_web::http::StatusCode::INTERNAL_SERVER_ERROR);
                            add_response_headers(&mut gateway_response, &response);
                            gateway_response.status(status_code);
                            gateway_response_body = Some(response.bytes_stream());
                        } else {
                            gateway_response.status(StatusCode::BAD_GATEWAY).body("Bad Gateway");
                        }
                    }
                }
            },
            PolicyHandler::Header { policy } => {
                policy.run(&mut gateway_response);
            },
        }
    }
    if let Some(body) = gateway_response_body {
        return gateway_response.streaming(body);
    } else {
        return gateway_response.finish();
    }
}


#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    let config = load_config("config.yaml");
    let (hostname_handlers, path_handlers) = register_handlers(&config);
    CONFIG.set(config).expect("Failed to set config");
    HOST_HANDLERS.set(hostname_handlers).expect("Failed to set host handlers");
    PATH_HANDLERS.set(path_handlers).expect("Failed to set path handlers");
    let default_ssl_config = SslConfig {
        key_path: "/etc/ssl/api1.nutespb.com.br/privkey.pem".into(),
        cert_path: "/etc/ssl/api1.nutespb.com.br/fullchain.pem".into(),
    };

    let http_client = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .danger_accept_invalid_certs(true).build().expect("couldn't initialize http reqwest client");
    let https_client = http_client.clone();
    
    if let Some(http) = &CONFIG.get().unwrap().http {
        let _ = HttpServer::new(move || {
            App::new()
                .app_data(web::Data::new(http_client.clone()))
                .app_data(web::PayloadConfig::new(10 * 1024 * 1024))
                .default_service(web::to(
                    |_: HttpRequest, _: web::Bytes, _: web::Data<reqwest::Client>| 
                    async move {
                        HttpResponse::NotFound().json(ErrorResponse {
                            error: "Domain not configured".into(),
                            details: None,
                            code: None,
                        })
                    }
                ))
        }).bind((http.hostname.clone(), http.port))?.run();
    }
    if let Some(https) = &CONFIG.get().unwrap().https {
        let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
        builder.set_private_key_file(&default_ssl_config.key_path, SslFiletype::PEM).unwrap();
        builder.set_certificate_chain_file(&default_ssl_config.cert_path).unwrap();

        // Set SNI callback
        builder.set_servername_callback(move |ssl, _| {
            if let Some(server_name) = ssl.servername(openssl::ssl::NameType::HOST_NAME) {
                if let Some(https) = CONFIG.get().unwrap().https.as_ref() {
                    if let Some(tls) = https.tls.get(server_name) {
                        let mut context = SslContext::builder(SslMethod::tls()).unwrap();
                        context.set_private_key_file(&tls.key, SslFiletype::PEM).unwrap();
                        context.set_certificate_chain_file(&tls.cert).unwrap();

                        ssl.set_ssl_context(&context.build()).unwrap();
                    }
                }
            }
            Ok(())
        });
        let _ = HttpServer::new(move || {
            let mut app = App::new();
            let paths = PATH_HANDLERS.get().unwrap().keys();
            app = app
                .app_data(web::Data::new(https_client.clone()))
                .app_data(web::PayloadConfig::new(10 * 1024 * 1024));
            for path in paths {
                app = app
                    .route(&path, web::to(
                        |req: HttpRequest, body: web::Bytes, client: web::Data<reqwest::Client>| {
                        async move {
                            let path = req.match_pattern().unwrap();
                            let handlers = PATH_HANDLERS.get().unwrap();
                            if let Some(path_handler) = handlers.get(&path){
                                let host: String = req.connection_info().host().to_string();
                                let method = req.method().to_string();
                                return match (path_handler.hosts.get(&host), &path_handler.action) {
                                    (Some(request_action), _) if request_action.methods.is_empty() || request_action.methods.contains(&method.to_string()) => {
                                        handler_request(request_action, &req, body, &client).await
                                    },
                                    (None, Some(request_action)) if request_action.methods.is_empty() || request_action.methods.contains(&method.to_string()) => {
                                        handler_request(request_action, &req, body, &client).await
                                    },
                                    (_, _) => {
                                        HttpResponse::Ok().json(ErrorResponse {
                                            error: "path not configured".into(),
                                            details: None,
                                            code: None,
                                        })
                                    }
                                };
                            }else{
                                HttpResponse::Ok().json(ErrorResponse {
                                    error: "path not configured".into(),
                                    details: None,
                                    code: None,
                                })
                            }                            
                        }
                    }));
            }
            app.default_service(web::to(
                |req: HttpRequest, body: web::Bytes, client: web::Data<reqwest::Client>|
                async move {
                    let host: String = req.connection_info().host().to_string();
                    let hostname_handlers = HOST_HANDLERS.get().unwrap();
                    if let Some(host_handler) = hostname_handlers.hosts.get(&host) {
                        if host_handler.action.methods.len() == 0 || host_handler.action.methods.contains(&req.method().to_string()) {
                            return handler_request(&host_handler.action, &req, body, &client).await;
                        }
                        return HttpResponse::NotFound().json(ErrorResponse {
                            error: "Method not configured".into(),
                            details: None,
                            code: None,
                        });
                    } else if let Some(request_action) = &hostname_handlers.action {
                        if request_action.methods.len() == 0 || request_action.methods.contains(&req.method().to_string()) {
                            return handler_request(request_action, &req, body, &client).await;
                        }
                    }
                    return HttpResponse::NotFound().json(ErrorResponse {
                        error: "Hostname not configured".into(),
                        details: None,
                        code: None,
                    });
                }
            ))
        }).bind_openssl((https.hostname.clone(), https.port), builder)?.run().await?;
    }
    Ok(())
}