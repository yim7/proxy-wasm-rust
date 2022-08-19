use std::collections::HashMap;

use anyhow::{anyhow, Result};
use log::{debug, info};
use proxy_wasm::traits::*;
use proxy_wasm::types::*;

mod sign;

#[no_mangle]
pub fn _start() {
    proxy_wasm::set_log_level(LogLevel::Trace);
    proxy_wasm::set_http_context(|context_id, _root_context| Box::new(ApiAuth { ctx: context_id }));
}

struct ApiAuth {
    ctx: u32,
}

impl ApiAuth {
    // fn check_need_reject(&mut self, ip: &str) -> bool {
    //     false
    // }

    fn reject(&self) {
        info!("api auth failed");
        self.send_http_response(403, vec![], Some(b"Access forbidden.\n"));
    }

    // fn get_client_ip(&self) -> String {
    //     self.get_http_request_header("x-true-client-ip")
    //         .unwrap_or_default()
    // }

    fn get_sign(&self) -> Result<String> {
        self.get_http_request_header("x-api-sign")
            .ok_or(anyhow!("no sign"))
    }

    fn get_timestamp(&self) -> Result<u64> {
        self.get_http_request_header("x-api-ts")
            .ok_or(anyhow!("no ts"))
            .and_then(|s| s.parse::<u64>().map_err(|_| anyhow!("parse ts error")))
    }

    fn get_nonce(&self) -> Result<String> {
        self.get_http_request_header("x-api-nonce")
            .ok_or(anyhow!("no nonce"))
    }

    fn get_version(&self) -> Result<String> {
        self.get_http_request_header("x-api-ver")
            .ok_or(anyhow!("no ver"))
    }

    fn get_payload(&self) -> Result<HashMap<String, String>> {
        // todo url decode
        let path = self.get_http_request_header(":path").unwrap_or_default();

        let payload = if let Some((_, query)) = path.split_once("?") {
            query
                .split("&")
                .map(|s| s.split_once("="))
                .filter_map(|kv| kv)
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect()
        } else {
            HashMap::new()
        };

        Ok(payload)
    }
}

impl Context for ApiAuth {}

impl HttpContext for ApiAuth {
    fn on_http_request_headers(&mut self, _num_headers: usize) -> Action {
        // extract sign params
        let sign = self.get_sign();
        let nonce = self.get_nonce();
        let ts = self.get_timestamp();
        let ver = self.get_version();
        let payload = self.get_payload();
        info!(
            "#{} -> sing: {:?}, nonce: {:?}, ts: {:?}, ver: {:?}, payload: {:?}",
            self.ctx, sign, nonce, ts, ver, payload
        );

        // validate signature
        let signed = match (sign, nonce, ts, ver, payload) {
            (Ok(sign1), Ok(nonce), Ok(ts), Ok(ver), Ok(payload)) => {
                let sign2 = sign::create_api_sign(payload, ts, &nonce, &ver);
                debug!("sign1: {}, sign2: {}", sign1, sign2);
                sign1 == sign2
            }
            _ => false,
        };

        if signed {
            Action::Continue
        } else {
            self.reject();
            Action::Pause
        }
    }
}
