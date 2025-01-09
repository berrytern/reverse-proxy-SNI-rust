use std::{collections::HashMap, sync::{Arc,Mutex}};
use crate::config::{
    config::{
    Config, Endpoint, EndpointType, HeaderPolicy, LogPolicy, PathType, Policies, ProxyPolicy, Service, URLType},
    handlers::{HostnameHandler, SpecificHostnameHandler, PathHandler, RequestAction}

};

fn feed_path_host(path_handler: &mut PathHandler, host: &String, methods: &Option<Vec<String>>, policies: &Vec<PolicyHandler>) {
    match path_handler.hosts.get_mut(host) {
        Some(request_action) => {
            if let Some(endpoint_methods) = methods {
                endpoint_methods.iter().for_each(|method| {
                    if !request_action.methods.contains(&method) {
                        request_action.methods.push(method.clone());
                    }
                });
            }
            request_action.policies = policies.clone();
        },
        None => {
            if host == "*" {
                match methods {
                    None =>{
                        path_handler.action = Some(RequestAction{methods: Vec::new(), policies: policies.clone()});
                    },
                    Some(methods) =>{
                        match &mut path_handler.action {
                            Some(action) =>{
                                methods.iter().for_each(|method| {
                                    if !action.methods.contains(&method) {
                                        action.methods.push(method.clone());
                                    }
                                });
                                action.policies = policies.clone();
                            },
                            None=> {
                                path_handler.action = Some(RequestAction{methods: methods.clone(), policies: policies.clone()});
                            }
                        }
                    }
                }
            } else {
                let mut action_methods = Vec::new();
                if let Some(endpoint_methods) = methods {
                    action_methods = endpoint_methods.clone();
                }
                let request_action = RequestAction{methods: action_methods, policies: policies.clone()};
                path_handler.hosts.insert(host.clone(), request_action);
            }
        }
    }
}

fn feed_host_handler(host_handler: &mut HostnameHandler, host: &String, path: &String, methods: &Option<Vec<String>>, policies: &Vec<PolicyHandler>) {
    if path == "*" {
        if host == "*" {
            match &mut host_handler.action {
                Some(request_action) => {
                    if let Some(endpoint_methods) = methods {
                        for method in endpoint_methods {
                            if !request_action.methods.contains(&method) {
                                request_action.methods.push(method.clone());
                            }
                        }
                        request_action.policies = policies.clone();
                    }
                },
                None => {
                    let mut action_methods = Vec::new();
                    if let Some(endpoint_methods) = methods {
                        action_methods = endpoint_methods.clone();
                    }
                    let request_action = RequestAction{methods: action_methods, policies: policies.clone()};
                    host_handler.action = Some(request_action);
                }
            } 
        } else {
            match host_handler.hosts.get_mut(host) {
                Some(specific_host_handler) => {
                    if let Some(endpoint_methods) = methods {
                        for method in endpoint_methods {
                            if !specific_host_handler.action.methods.contains(&method) {
                                specific_host_handler.action.methods.push(method.clone());
                            }
                        }
                        specific_host_handler.action.policies = policies.clone();
                    }
                },
                None => {
                    let mut action_methods = Vec::new();
                    if let Some(endpoint_methods) = methods {
                        action_methods = endpoint_methods.clone();
                    }
                    let specific_host_handler = SpecificHostnameHandler{action:RequestAction{methods: action_methods, policies: policies.clone()}};
                    host_handler.hosts.insert(host.clone(), specific_host_handler);
                }
            }
        }
    }
    
}


fn process_endpoint(policies: &Vec<PolicyHandler>, endpoint: &Endpoint, host_handler: &mut HostnameHandler, path_host: &mut HashMap<String, PathHandler>) {
    match &endpoint.paths {
        PathType::Vec(endpoint_paths) => {
            for path in endpoint_paths{
                feed_host_handler(host_handler, &endpoint.host, path, &endpoint.methods, policies);
                match path_host.get_mut(path){
                    Some(path_handler) => {
                        feed_path_host(path_handler, path, &endpoint.methods, policies);
                    }
                    None => {
                        let mut path_handler = PathHandler{hosts: HashMap::new(), action: None};
                        feed_path_host(&mut path_handler, path, &endpoint.methods, policies);
                        path_host.insert(path.clone(), path_handler);
                    },
                }
            }
        },
        PathType::String(path) => {
            feed_host_handler(host_handler, &endpoint.host, path, &endpoint.methods, policies);
            match path_host.get_mut(path){
                Some(path_handler) => {
                    feed_path_host(path_handler, path, &endpoint.methods, policies);
                }
                None => {
                    let mut path_handler = PathHandler{hosts: HashMap::new(), action: None};
                    feed_path_host(&mut path_handler, path, &endpoint.methods, policies);
                    path_host.insert(path.clone(), path_handler);
                },
            }
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

pub fn register_handlers(cf: &Config) -> (HostnameHandler, HashMap<String, PathHandler>) {
    let mut host_handler: HostnameHandler = HostnameHandler{hosts: HashMap::new(), action: None};
    let mut paths: HashMap<String, PathHandler> = HashMap::new();
    for pipelines in cf.pipelines.values() {
        let policies = pipeline_to_function(&pipelines.policies, &cf.service_endpoints);
        for endpoint_key in &pipelines.api_endpoints {
            if let Some(endpoint_vec) = cf.api_endpoints.get(endpoint_key){
                match endpoint_vec {
                    EndpointType::VecEndpoint(endpoint_vec) => {
                        for endpoint in endpoint_vec {
                            process_endpoint(&policies, &endpoint, &mut host_handler, &mut paths);
                        }
                    },
                    EndpointType::Endpoint(endpoint) => {
                        process_endpoint(&policies, &endpoint, &mut host_handler, &mut paths);
                    }
                }
            }
        }
    }
    return (host_handler, paths) ;
}