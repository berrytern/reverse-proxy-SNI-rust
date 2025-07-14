use crate::infrastructure::yaml::load_handlers::PolicyHandler;
use std::collections::HashMap;

#[derive(Debug)]
pub struct HostnameHandler {
    pub hosts: HashMap<String, SpecificHostnameHandler>,
    pub action: Option<RequestAction>,
}
#[derive(Debug)]
pub struct SpecificHostnameHandler {
    pub action: RequestAction,
}

#[derive(Debug)]
pub struct PathHandler {
    pub hosts: HashMap<String, RequestAction>,
    pub action: Option<RequestAction>,
}

#[derive(Debug)]
pub struct RequestAction {
    pub methods: Vec<String>,
    pub policies: Vec<PolicyHandler>,
}
