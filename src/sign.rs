use std::collections::HashMap;

use itertools::Itertools;
use sha1::{Digest, Sha1};

pub fn create_api_sign(
    payload: HashMap<String, String>,
    timestap: u64,
    nonce: &str,
    version: &str,
) -> String {
    let mut payload = payload.clone();
    payload.extend([
        ("ts".to_string(), timestap.to_string()),
        ("n".to_string(), nonce.to_string()),
        ("v".to_string(), version.to_string()),
    ]);

    let sorted_keys = payload.keys().sorted();

    let raw = sorted_keys
        .map(|key| format!("{}={}", key, payload[key]))
        .join("&");

    let mut hasher = Sha1::new();
    hasher.update(raw);
    let result = hasher.finalize();

    format!("{:x}", result)
}
