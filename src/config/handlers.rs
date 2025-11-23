use crate::infrastructure::yaml::load_handlers::PolicyHandler;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct HostnameHandler {
    pub hosts: HashMap<String, SpecificHostnameHandler>,
    pub action: Option<RequestAction>,
}
#[derive(Debug, Clone)]
pub struct SpecificHostnameHandler {
    pub action: RequestAction,
}

#[derive(Debug, Clone)]
pub struct PathHandler {
    pub hosts: HashMap<String, RequestAction>,
    pub action: Option<RequestAction>,
}

#[derive(Debug, Clone)]
pub struct RequestAction {
    pub methods: Vec<String>,
    pub policies: Vec<PolicyHandler>,
}
