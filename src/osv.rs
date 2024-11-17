use serde::{Deserialize, Serialize};

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Request {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub commit: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub version: String,
    pub package: Package,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub next_page_token: String
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Response {
    pub vulns: Vec<Vuln>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]

pub struct Vuln {
    pub id: String,
    #[serde(default)]
    pub summary: String,
    pub details: String,
    pub modified: String,
    #[serde(default)]
    pub related: Vec<String>,
    #[serde(default)]
    pub aliases: Vec<String>,
    pub published: String,
    pub references: Vec<Reference>,
    pub affected: Vec<Affected>,
    #[serde(rename = "schema_version")]
    pub schema_version: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]

pub struct Reference {
    #[serde(rename = "type")]
    pub type_field: String,
    pub url: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]

pub struct Affected {
    pub package: Package,
    pub ranges: Vec<Range>,
    pub versions: Vec<String>,
    #[serde(rename = "ecosystem_specific")]
    #[serde(default)]
    pub ecosystem_specific: EcosystemSpecific,
    #[serde(default)]
    #[serde(rename = "database_specific")]
    pub database_specific: DatabaseSpecific,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]

pub struct Package {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub ecosystem: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub purl: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]

pub struct Range {
    #[serde(rename = "type")]
    pub type_field: String,
    #[serde(default)]
    pub repo: String,
    pub events: Vec<Event>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]

pub struct Event {
    pub introduced: Option<String>,
    pub fixed: Option<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]

pub struct EcosystemSpecific {
    #[serde(default)]
    pub severity: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]

pub struct DatabaseSpecific {
    pub source: String,
}
