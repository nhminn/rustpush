
use std::{collections::HashMap, sync::{LazyLock, Mutex}, time::{Duration, Instant, SystemTime}};

use async_trait::async_trait;
use plist::{Data, Dictionary, Value};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{activation::ActivationInfo, util::{encode_hex, get_bag, REQWEST, plist_to_buf, IDS_BAG}, DebugMeta, OSConfig, PushError, RegisterMeta};

pub use open_absinthe::nac::HardwareConfig;

/// A validation stamp minted by the app (the open-madrid NAC mint) and handed to
/// Rust before sign-in. Apple stamps are short-lived, so keep the cache small and
/// reject anything older than ten minutes.
struct ValidationDataCache {
    session250: Vec<u8>,
    data: Vec<u8>,
    created: Instant,
}

static VALIDATION_DATA: LazyLock<Mutex<Option<ValidationDataCache>>> =
    LazyLock::new(|| Mutex::new(None));

pub fn set_validation_data(session250: Vec<u8>, data: Vec<u8>) {
    *VALIDATION_DATA.lock().unwrap() = Some(ValidationDataCache {
        session250,
        data,
        created: Instant::now(),
    });
}

fn get_validation_data(session250: &[u8]) -> Option<Vec<u8>> {
    let guard = VALIDATION_DATA.lock().unwrap();
    let cache = guard.as_ref()?;
    if cache.session250 != session250 || cache.created.elapsed() > Duration::from_secs(600) {
        return None;
    }
    Some(cache.data.clone())
}

pub fn clear_validation_data() {
    *VALIDATION_DATA.lock().unwrap() = None;
}

/// `HardwareConfig::to_bin`, the 250-byte session material consumed by the NAC mint.
///
/// This is the byte-verified grammar documented by open-madrid (spec §1.1 C56-c):
/// length-prefixed strings, the raw 6-byte MAC, a constant dword, then seven
/// length-prefixed binary items in Mac-Hardware-Info export order.
pub fn hardware_config_to_bin(hw: &HardwareConfig) -> Result<Vec<u8>, PushError> {
    fn write_str(out: &mut Vec<u8>, value: &str) -> Result<(), PushError> {
        let bytes = value.as_bytes();
        if bytes.len() >= 255 {
            return Err(PushError::ValidationDataUnavailable(
                "hardware configuration string is too long".to_string(),
            ));
        }
        out.push((bytes.len() + 1) as u8);
        out.extend_from_slice(bytes);
        out.push(0);
        Ok(())
    }

    fn write_item(out: &mut Vec<u8>, value: &[u8]) -> Result<(), PushError> {
        if value.len() > 255 {
            return Err(PushError::ValidationDataUnavailable(
                "hardware configuration blob is too long".to_string(),
            ));
        }
        out.push(value.len() as u8);
        out.extend_from_slice(value);
        Ok(())
    }

    let mut out = Vec::with_capacity(250);
    write_str(&mut out, &hw.product_name)?;
    out.extend_from_slice(&hw.io_mac_address);
    write_str(&mut out, &hw.platform_serial_number)?;
    write_str(&mut out, &hw.platform_uuid)?;
    write_str(&mut out, &hw.root_disk_uuid)?;
    write_str(&mut out, &hw.board_id)?;
    write_str(&mut out, &hw.os_build_num)?;
    out.extend_from_slice(&[0x00, 0x03, 0x0b, 0x52]);
    write_item(&mut out, &hw.platform_serial_number_enc)?;
    write_item(&mut out, &hw.platform_uuid_enc)?;
    write_item(&mut out, &hw.root_disk_uuid_enc)?;
    write_item(&mut out, &hw.rom)?;
    write_item(&mut out, &hw.rom_enc)?;
    write_item(&mut out, hw.mlb.as_bytes())?;
    write_item(&mut out, &hw.mlb_enc)?;
    Ok(out)
}

/// Step 1 of the validation exchange: the `id-validation-cert` chain.
pub async fn fetch_validation_cert() -> Result<Vec<u8>, PushError> {
    let url = get_bag(IDS_BAG, "id-validation-cert").await?.into_string().unwrap();
    let response = REQWEST.get(url).send().await?;
    if !response.status().is_success() {
        return Err(PushError::StatusError(response.status()));
    }
    let response: CertsResponse = plist::from_bytes(&response.bytes().await?)?;
    Ok(response.cert.into())
}

/// Step 2 of the validation exchange: POST the session-info-request and return
/// the server's `session-info` blob.
pub async fn initialize_validation(request: Vec<u8>) -> Result<Vec<u8>, PushError> {
    let init = SessionInfoRequest {
        session_info_request: request.into(),
    };
    let info = plist_to_buf(&init)?;
    let url = get_bag(IDS_BAG, "id-initialize-validation").await?.into_string().unwrap();
    let response = REQWEST.post(url).body(info).send().await?;
    if !response.status().is_success() {
        return Err(PushError::StatusError(response.status()));
    }
    let response: SessionInfoResponse = plist::from_bytes(&response.bytes().await?)?;
    Ok(response.session_info.into())
}

#[derive(Serialize, Deserialize, Clone)]
pub struct MacOSConfig {
    pub inner: HardwareConfig,

    // software
    pub version: String,
    pub protocol_version: u32,
    pub device_id: String,
    pub icloud_ua: String,
    pub aoskit_version: String,
    pub udid: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct SessionInfoRequest {
    session_info_request: Data,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
struct SessionInfoResponse {
    session_info: Data,
}

#[derive(Deserialize)]
struct CertsResponse {
    cert: Data,
}

#[async_trait]
impl OSConfig for MacOSConfig {
    fn build_activation_info(&self, csr: Vec<u8>) -> ActivationInfo {
        ActivationInfo {
            activation_randomness: Uuid::new_v4().to_string().to_uppercase(),
            activation_state: "Unactivated",
            build_version: self.inner.os_build_num.clone(),
            device_cert_request: csr.into(),
            device_class: "MacOS".to_string(),
            product_type: self.inner.product_name.clone(),
            product_version: self.version.clone(),
            serial_number: self.inner.platform_serial_number.clone(),
            unique_device_id: self.device_id.clone().to_uppercase(),
        }
    }

    fn get_udid(&self) -> String {
        self.udid.clone().expect("missing udid!")
    }

    fn get_normal_ua(&self, item: &str) -> String {
        let part = self.icloud_ua.split_once(char::is_whitespace).unwrap().0;
        format!("{item} {part}")
    }

    fn get_aoskit_version(&self) -> String {
        self.aoskit_version.clone()
    }

    fn get_mme_clientinfo(&self, for_item: &str) -> String {
        format!("<{}> <macOS;{};{}> <{}>", self.inner.product_name, self.version, self.inner.os_build_num, for_item)
    }

    fn get_version_ua(&self) -> String {
        format!("[macOS,{},{},{}]", self.version, self.inner.os_build_num, self.inner.product_name)
    }

    fn get_activation_device(&self) -> String {
        "MacOS".to_string()
    }

    fn get_device_uuid(&self) -> String {
        self.device_id.clone()
    }

    fn get_device_name(&self) -> String {
        format!("Mac-{}", self.inner.platform_serial_number)
    }

    async fn generate_validation_data(&self) -> Result<Vec<u8>, PushError> {
        let session250 = hardware_config_to_bin(&self.inner)?;
        if let Some(data) = get_validation_data(&session250) {
            return Ok(data);
        }

        // The public OpenAbsinthe dependency is a stub. The real mint lives in the
        // app's vendored Kotlin implementation; the Dart setup flow mints a stamp
        // and installs it here before the delegate login / IDS registration.
        Err(PushError::ValidationDataUnavailable(
            "no validation data was prepared for this hardware".to_string(),
        ))
    }

    fn get_protocol_version(&self) -> u32 {
        self.protocol_version
    }

    fn get_register_meta(&self) -> RegisterMeta {
        RegisterMeta {
            hardware_version: self.inner.product_name.clone(),
            os_version: format!("macOS,{},{}", self.version, self.inner.os_build_num),
            software_version: self.inner.os_build_num.clone(),
        }
    }

    fn get_debug_meta(&self) -> DebugMeta {
        DebugMeta {
            user_version: self.version.clone(),
            hardware_version: self.inner.product_name.clone(),
            serial_number: self.inner.platform_serial_number.clone(),
        }
    }

    fn get_gsa_hardware_headers(&self) -> HashMap<String, String> {
        [
            ("X-Apple-I-MLB", self.inner.mlb.as_str()),
            ("X-Apple-I-ROM", &encode_hex(&self.inner.rom)), // intentional lowercase
            ("X-Apple-I-SRL-NO", &self.inner.platform_serial_number),
        ].into_iter().map(|(a, b)| (a.to_string(), b.to_string())).collect()
    }

    fn get_serial_number(&self) -> String {
        self.inner.platform_serial_number.clone()
    }

    fn get_login_url(&self) -> &'static str {
        "https://setup.icloud.com/setup/signin/v2/login"
    }

    fn get_private_data(&self) -> Dictionary {
        let apple_epoch = SystemTime::UNIX_EPOCH + Duration::from_secs(978307200);
        Dictionary::from_iter([
            ("ap", Value::String("0".to_string())), // 1 for ios

            ("d", Value::String(format!("{:.6}", apple_epoch.elapsed().unwrap().as_secs_f64()))),
            ("dt", Value::Integer(1.into())),
            ("gt", Value::String("0".to_string())),
            ("h", Value::String("1".to_string())),
            ("m", Value::String("0".to_string())),
            ("p", Value::String("0".to_string())),

            ("pb", Value::String(self.inner.os_build_num.clone())),
            ("pn", Value::String("macOS".to_string())),
            ("pv", Value::String(self.version.clone())),

            ("s", Value::String("0".to_string())),
            ("t", Value::String("0".to_string())),
            ("u", Value::String(self.device_id.clone().to_uppercase())),
            ("v", Value::String("1".to_string())),
        ])
    }
}
