
use std::{collections::HashMap, time::{Duration, SystemTime}};

use async_trait::async_trait;
use plist::{Dictionary, Value};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::{activation::ActivationInfo, util::{base64_decode, REQWEST}, DebugMeta, OSConfig, PushError, RegisterMeta};

#[derive(Deserialize)]
pub struct DataResp {
    data: String,
}

#[derive(Deserialize)]
pub struct VersionsResp {
    versions: Versions,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Versions {
    software_build_id: String,
    software_name: String,
    software_version: String,
    serial_number: String,
    hardware_version: String,
    unique_device_id: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct RelayConfig {
    pub version: Versions,
    pub icloud_ua: String,
    pub aoskit_version: String,
    pub dev_uuid: String,
    pub protocol_version: u32,
    pub host: String,
    pub code: String,
    pub beeper_token: Option<String>,
    pub udid: Option<String>,
}

impl Versions {
    /// Map the relay's reported macOS to the CFNetwork + Darwin build that
    /// shipped with it, so every client UA we emit stays coherent with the OS
    /// the validation data was minted on (Apple flags OS/UA contradictions).
    fn cfnetwork_darwin(&self) -> (&'static str, &'static str) {
        let v = self.software_version.as_str();
        if v.starts_with("10.14") { ("978.0.7", "18.7.0") }       // Mojave
        else if v.starts_with("10.15") { ("1128.0.1", "19.6.0") } // Catalina
        else if v.starts_with("11.") { ("1240.0.4", "20.6.0") }   // Big Sur
        else if v.starts_with("12.") { ("1404.0.5", "21.6.0") }   // Monterey
        else if v.starts_with("13.") { ("1408.0.4", "22.5.0") }   // Ventura
        else if v.starts_with("14.") { ("1496.0.7", "23.6.0") }   // Sonoma
        else { ("1408.0.4", "22.5.0") }
    }

    /// iCloudHelper UA matching the relay OS. The app build (282) is left as-is
    /// because Apple doesn't validate it against the OS, only CFNetwork/Darwin.
    pub fn icloud_user_agent(&self) -> String {
        let (cfnetwork, darwin) = self.cfnetwork_darwin();
        format!("com.apple.iCloudHelper/282 CFNetwork/{cfnetwork} Darwin/{darwin}")
    }

    /// akd (AuthKit daemon) UA matching the relay OS, sent during GSA.
    pub fn akd_user_agent(&self) -> String {
        let (cfnetwork, darwin) = self.cfnetwork_darwin();
        format!("akd/1.0 CFNetwork/{cfnetwork} Darwin/{darwin}")
    }
}

impl RelayConfig {
    pub async fn get_versions(host: &str, code: &str, beeper_token: &Option<String>) -> Result<Versions, PushError> {
        let mut data = REQWEST.post(format!("{}/api/v1/bridge/get-version-info", host))
            .bearer_auth(code)
            .header("Content-Length", "0");

        if let Some(token) = beeper_token {
            data = data.header("X-Beeper-Access-Token", token.clone());
        }

        let result = data.send().await?;

        match result.status().as_u16() {
            200 => {},
            404 => {
                return Err(PushError::DeviceNotFound)
            },
            _status => {
                return Err(PushError::RelayError(_status, result.text().await?))
            }
        }

        let result: VersionsResp = result.json().await?;

        Ok(result.versions)
    }
}

#[async_trait]
impl OSConfig for RelayConfig {
    fn build_activation_info(&self, csr: Vec<u8>) -> ActivationInfo {
        // The Albert push-cert activation is ALWAYS done as DeviceClass=MacOS.
        // The bundled FairPlay keys are generic Mac activation keys; Albert only
        // mints a push cert for the MacOS class. A real device=iPhone activation
        // needs the iPhone SEP's own FairPlay signature (which the relay does not
        // expose), and sending DeviceClass=iPhone here makes Albert reply
        // "Device Unknown". This matches upstream OpenBubbles, which activates as
        // a Mac even when the validation-data provider is an iPhone. The iPhone
        // identity lives in the validation-data + register-meta, not here.
        ActivationInfo {
            activation_randomness: Uuid::new_v4().to_string().to_uppercase(),
            activation_state: "Unactivated",
            build_version: self.version.software_build_id.clone(),
            device_cert_request: csr.into(),
            device_class: "MacOS".to_string(),
            product_type: "iMac13,1".to_string(),
            product_version: self.version.software_version.clone(),
            serial_number: self.version.serial_number.clone(),
            unique_device_id: self.version.unique_device_id.clone().to_uppercase(),
        }
    }

    fn get_udid(&self) -> String {
        self.udid
            .clone()
            .unwrap_or_else(|| self.version.unique_device_id.clone().to_uppercase())
    }

    fn get_normal_ua(&self, item: &str) -> String {
        let part = self.icloud_ua.split_once(char::is_whitespace).unwrap().0;
        format!("{item} {part}")
    }

    fn get_serial_number(&self) -> String {
        self.version.serial_number.clone()
    }

    fn get_mme_clientinfo(&self, item: &str) -> String {
        format!("<{}> <{};{};{}> <{}>", self.version.hardware_version, self.version.software_name, self.version.software_version, self.version.software_build_id, item)
    }

    fn get_adi_mme_info(&self, item: &str, _require_mac: bool) -> String {
        // The relay is itself a Mac, so always report its real OS rather than a
        // hardcoded model. Keeps ClearADI/anisette client info matching the VM.
        self.get_mme_clientinfo(item)
    }

    fn get_aoskit_version(&self) -> String {
        self.aoskit_version.clone()
    }

    fn get_akd_user_agent(&self) -> String {
        self.version.akd_user_agent()
    }

    fn get_gsa_hardware_headers(&self) -> HashMap<String, String> {
        [
            ("X-Apple-I-SRL-NO", &self.version.serial_number),
        ].into_iter().map(|(a, b)| (a.to_string(), b.to_string())).collect()
    }

    fn get_version_ua(&self) -> String {
        format!("[{},{},{},{}]", self.version.software_name, self.version.software_version, self.version.software_build_id, self.version.hardware_version)
    }

    fn get_login_url(&self) -> &'static str {
        "https://setup.icloud.com/setup/signin/v2/login"
    }

    fn get_activation_device(&self) -> String {
        // Push-cert activation is always MacOS class (see build_activation_info).
        "MacOS".to_string()
    }

    fn get_device_uuid(&self) -> String {
        self.dev_uuid.clone()
    }

    fn get_device_name(&self) -> String {
        format!("iPhone-{}", self.version.serial_number)
    }

    fn get_protocol_version(&self) -> u32 {
        self.protocol_version
    }

    async fn generate_validation_data(&self) -> Result<Vec<u8>, PushError> {
        let mut data = REQWEST.post(format!("{}/api/v1/bridge/get-validation-data", self.host))
            .bearer_auth(&self.code)
            .header("Content-Length", "0");

        if let Some(token) = &self.beeper_token {
            data = data.header("X-Beeper-Access-Token", token.clone());
        }

        let result = data.send().await?;

        match result.status().as_u16() {
            200 => {},
            404 => {
                return Err(PushError::DeviceNotFound)
            },
            _status => {
                return Err(PushError::RelayError(_status, result.text().await?))
            }
        }

        let result: DataResp = result.json().await?;

        Ok(base64_decode(&result.data))
    }

    fn get_register_meta(&self) -> RegisterMeta {
        RegisterMeta {
            hardware_version: self.version.hardware_version.clone(),
            os_version: format!("{},{},{}", self.version.software_name, self.version.software_version, self.version.software_build_id),
            software_version: self.version.software_build_id.clone(),
        }
    }

    fn get_debug_meta(&self) -> DebugMeta {
        DebugMeta {
            user_version: self.version.software_version.clone(),
            hardware_version: self.version.hardware_version.clone(),
            serial_number: self.version.serial_number.clone(),
        }
    }

    fn get_private_data(&self) -> Dictionary {
        let apple_epoch = SystemTime::UNIX_EPOCH + Duration::from_secs(978307200);
        Dictionary::from_iter([
            // apple pay
            ("ap", Value::String("0".to_string())),

            ("d", Value::String(format!("{:.6}", apple_epoch.elapsed().unwrap().as_secs_f64()))),
            // device type
            ("dt", Value::Integer(1.into())),
            // green tea - ??
            ("gt", Value::String("0".to_string())),
            // supports handoff
            ("h", Value::String("1".to_string())),
            // supports phone calls
            ("p", Value::String("0".to_string())),

            ("pb", Value::String(self.version.software_build_id.clone())),
            ("pn", Value::String(if self.version.software_name == "MacOS" { "macOS".to_string() } else { self.version.software_name.clone() })),
            ("pv", Value::String(self.version.software_version.clone())),
            
            // mms router support
            ("m", Value::String("1".to_string())),
            // sms router support
            ("s", Value::String("1".to_string())),

            // tethering support
            // ec = enclosure color
            // c = data color
            // ss = service signatures
            // ktf = key transparency flags
            // ktv = key transparency version
            ("t", Value::String("0".to_string())),
            ("u", Value::String(self.dev_uuid.clone().to_uppercase())),
            // version
            ("v", Value::String("1".to_string())),
        ])
    }

}
