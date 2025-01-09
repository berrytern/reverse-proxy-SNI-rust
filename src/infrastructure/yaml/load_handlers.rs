use std::{collections::HashMap, sync::{Arc,Mutex}};
use crate::config::{
    config::{
    Config, Endpoint, EndpointType, HeaderPolicy, LogPolicy, PathType, Policies, ProxyPolicy, Service, URLType},
    handlers::{HostHandler, RequestAction}

};

pub fn process_endpoint(endpoint: &Endpoint, host_path: &mut HashMap<String, HostHandler>, policies: &Vec<PolicyHandler>) {
    match host_path.get_mut(&endpoint.host) {
        Some(host_handler) => {
            match &endpoint.paths {
                PathType::Vec(endpoint_paths) => {
                    if endpoint_paths.len() == 0 {
                        host_handler.action = Some(RequestAction{methods: endpoint.methods.clone().unwrap_or(Vec::new()), policies: policies.clone()});
                    }
                    for path in endpoint_paths {
                        match host_handler.paths.get_mut(path) {
                            Some(request_action) => {
                                match &endpoint.methods {
                                    Some(endpoint_methods) => {
                                        for method in endpoint_methods {
                                            if !request_action.methods.contains(&method) {
                                                request_action.methods.push(method.clone());
                                            }
                                        }
                                    },
                                    None => {}
                                }
                            },
                            None => {
                                if let Some(methods) = &endpoint.methods {
                                    let request_action = RequestAction{methods: methods.clone(), policies: policies.clone()};
                                    host_handler.paths.insert(path.clone(), request_action);
                                }
                            }
                        }
                    }
                },
                PathType::String(path) => {
                    if *path == "*" {
                        host_handler.action = Some(RequestAction{methods: endpoint.methods.clone().unwrap_or(Vec::new()), policies: policies.clone()});
                    }
                    match host_handler.paths.get_mut(path) {
                        Some(request_action) => {
                            match &endpoint.methods {
                                Some(endpoint_methods) => {
                                    for method in endpoint_methods {
                                        if !request_action.methods.contains(&method) {
                                            request_action.methods.push(method.clone());
                                        }
                                    }
                                },
                                None => {}
                            }
                        },
                        None => {
                            if let Some(methods) = &endpoint.methods {
                                let request_action = RequestAction{methods: methods.clone(), policies: policies.clone()};
                                host_handler.paths.insert(path.clone(), request_action);
                            }
                        }
                    }
                }
            }
        },
        None => {
            let mut host_handler: HostHandler = HostHandler{paths: HashMap::new(), action: None};
            match &endpoint.paths {
                PathType::Vec(endpoint_paths) => {
                    for path in endpoint_paths {
                        match host_handler.paths.get_mut(path) {
                            Some(request_action) => {
                                match &endpoint.methods {
                                    Some(endpoint_methods) => {
                                        for method in endpoint_methods {
                                            if !request_action.methods.contains(&method) {
                                                request_action.methods.push(method.clone());
                                            }
                                        }
                                    },
                                    None => {}
                                }
                            },
                            None => {
                                if let Some(methods) = &endpoint.methods {
                                    let request_action = RequestAction{methods: methods.clone(), policies: policies.clone()};
                                    host_handler.paths.insert(path.clone(), request_action);
                                }
                            }
                        }
                    }
                },
                PathType::String(path) => {
                    if path == "*" {
                        host_handler.action = Some(RequestAction{methods: endpoint.methods.clone().unwrap_or(Vec::new()), policies: policies.clone()});
                    }
                    let mut methods = Vec::new();
                    if let Some(endpoint_methods) = &endpoint.methods {
                        methods = endpoint_methods.clone();
                    }
                    let request_action = RequestAction{methods: methods, policies: policies.clone()};
                    host_handler.paths.insert(path.clone(), request_action);
                }
            }
            host_path.insert(endpoint.host.clone(), host_handler);
        }
    }
}

#[derive(Debug, Clone)]
pub enum PolicyHandler {
    Log { policy: LogPolicy },
    Proxy { policy: ProxyPolicy, target: URLType, count: Arc<Mutex<u8>>, size: u8 },
    Header { policy: HeaderPolicy },
}


fn pipeline_to_function(policies: &Vec<Policies>, services: &HashMap<String, Service>) -> Vec<PolicyHandler>{
    let mut actions: Vec<PolicyHandler> = Vec::new();
    for policy in policies {
        match policy {
            Policies::LogPolicy(log_policy) => {
                actions.push(PolicyHandler::Log { policy: log_policy.clone() })
            },
            Policies::ProxyPolicy(proxy_policy) => {
                if let Some(service) = services.get(&proxy_policy.proxy.action.service_endpoint) {
                    let size = match &service.url {
                        URLType::String(_) => 1,
                        URLType::Vec(urls) => urls.len(),
                    };
                    actions.push(PolicyHandler::Proxy { policy: proxy_policy.clone(), target: service.url.clone(), count: Arc::new(Mutex::new(0)), size: size as u8 });
                }
            },
            Policies::HeaderPolicy(header_policy) => {
                actions.push(PolicyHandler::Header { policy: header_policy.clone() })
            },
        }
    }
    actions
}

pub fn register_handlers(cf: &Config) -> HashMap<String, HostHandler> {
    let mut hosts: HashMap<String, HostHandler> = HashMap::new();
    
    for pipelines in cf.pipelines.values() {
        let policies = pipeline_to_function(&pipelines.policies, &cf.service_endpoints);
        for endpoint_key in &pipelines.api_endpoints {
            if let Some(endpoint_vec) = cf.api_endpoints.get(endpoint_key){
                match endpoint_vec {
                    EndpointType::VecEndpoint(endpoint_vec) => {
                        for endpoint in endpoint_vec {
                            process_endpoint(&endpoint, &mut hosts, &policies);
                        }
                    },
                    EndpointType::Endpoint(endpoint) => {
                        process_endpoint(&endpoint, &mut hosts, &policies);
                    }
                }
            }
        }
    }
    return hosts;
}