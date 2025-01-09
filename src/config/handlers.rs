use std::collections::HashMap;
use crate::infrastructure::yaml::load_handlers::PolicyHandler;

#[derive(Debug)]
pub struct HostHandler {
    pub paths: HashMap<String, RequestAction>,
    pub action: Option<RequestAction>,
}

#[derive(Debug)]
pub struct RequestAction {
    pub methods: Vec<String>,
    pub policies: Vec<PolicyHandler>,
}
