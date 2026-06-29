
use std::{collections::HashMap, fs::File, io::{Cursor, Read}, num::ParseIntError, path::{Path, PathBuf}, sync::{Arc, Mutex}, time::{Duration, SystemTime}};

use aes_siv::{Aes256SivAead, Nonce};
use base64::{alphabet::STANDARD, engine::general_purpose};
use cloudkit_derive::CloudKitRecord;
use cloudkit_proto::{CloudKitRecord, CloudKitValue, CuttlefishSerializedKey, ZoneRetrieveRequest, base64_encode};
use hkdf::Hkdf;
use icloud_auth::{AppleAccount, LoginState};
use keystore::{init_keystore, software::{NoEncryptor, SoftwareEncryptor, SoftwareKeystore}};
use log::{debug, error, info, warn};
use omnisette::{default_provider, AnisetteHeaders, DefaultAnisetteProvider};
use open_absinthe::nac::HardwareConfig;
use openssl::{bn::BigNumContext, ec::{EcKey, PointConversionForm}, rsa::Rsa, sha::sha256};
use plist::{Data, Dictionary, Value};
use rustpush::{APSConnectionResource, APSState, Attachment, Bbox, bbox_id_query, bbox_id_query_raw, CircleClientSession, CircleServerSession, CompactECKey, ConversationData, DebugMutex, DebugRwLock, EntitlementAuthState, FileContainer, IDSNGMIdentity, IDSUser, IDSUserIdentity, IMClient, IdmsAuthListener, IdmsMessage, IndexedMessagePart, KeyedArchive, LoginDelegate, MADRID_SERVICE, MMCSFile, Message, MessageInst, MessageParts, MessageType, NormalMessage, PushError, RelayConfig, ShareProfileMessage, SharedPoster, TokenProvider, UpdateAccountFinish, UpdateProfileMessage, authenticate_apple, authenticate_smsless, cloud_messages::{CloudMessagesClient, MESSAGES_SERVICE}, cloudkit::{CloudKitClient, CloudKitContainer, CloudKitSession, CloudKitState, DeleteRecordOperation, FetchZoneOperation, ZoneDeleteOperation, ZoneSaveOperation, record_identifier}, facetime::{FACETIME_SERVICE, FTClient, FTMember, FTMessage, FTState, VIDEO_SERVICE}, findmy::{BeaconNamingRecord, FindMyClient, FindMyState, FindMyStateManager, MULTIPLEX_SERVICE}, get_gateways_for_mccmnc, keychain::{CloudKey, KEYCHAIN_ZONES, KeychainClient, KeychainClientState}, login_apple_delegates, macos::MacOSConfig, name_photo_sharing::{IMessageNameRecord, IMessageNicknameRecord, IMessagePosterRecord, ProfilesClient}, passwords::{PasswordManager, PasswordState, SHARED_PASSWORDS_SERVICE}, pcs::{PCSKey, PCSPrivateKey}, posterkit::{PhotoPosterContentsFrame, PosterType, SimplifiedIncomingCallPoster, SimplifiedPoster, SimplifiedTranscriptPoster, TranscriptDynamicUserData}, prepare_put, register, request_update_account, sharedstreams::{AssetDetails, AssetFile, AssetMetadata, CollectionMetadata, FFMpegFilePackager, FileMetadata, FilePackager, PreparedAsset, PreparedFile, SharedStreamClient, SharedStreamsState, SyncController, SyncState, round_seconds}, statuskit::{StatusKitClient, StatusKitState, StatusKitStatus}};
use sha2::Sha256;
use tokio::{fs, io::{self, AsyncBufReadExt, BufReader}, process::Command, sync::RwLock};
use tokio::io::AsyncWriteExt;
use uuid::Uuid;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use zip::ZipArchive;
use std::io::Write;
use base64::Engine;
use std::str::FromStr;
use std::io::Seek;
use rustpush::OSConfig;
use std::fmt::Write as FmtWrite;
use omnisette::AnisetteProvider;

#[derive(Serialize, Deserialize, Clone)]
struct SavedState {
    push: APSState,
    users: Vec<IDSUser>,
    identity: IDSNGMIdentity,
}

fn sort_value(value: &mut Value) {
    match value {
        Value::Array(arr) => {
            for i in arr {
                sort_value(i);
            }
        },
        Value::Dictionary(dict) => {
            dict.sort_keys();
            for val in dict.values_mut() {
                sort_value(val);
            }
        },
        _ => {}
    }
}
fn read_file<T: Read + Seek, R: DeserializeOwned>(archive: &mut ZipArchive<T>, path: &str) -> Result<R, PushError> {
    let mut manifest = vec![];
    archive.by_name(path)?.read_to_end(&mut manifest)?;
    Ok(plist::from_bytes(&manifest)?)
}

fn read_archive<T: Read + Seek, R: DeserializeOwned>(archive: &mut ZipArchive<T>, path: &str) -> Result<R, PushError> {
    let mut manifest = vec![];
    archive.by_name(path)?.read_to_end(&mut manifest)?;
    Ok(plist::from_value(&KeyedArchive::expand_root(&manifest)?)?)
}

pub fn parse_poster(poster: &IMessagePosterRecord) -> Result<String, PushError> {
    let meta: Value = plist::from_bytes(&poster.meta)?;

    let mut archive = ZipArchive::new(Cursor::new(&poster.package))?;
    let manifest: Value = read_file(&mut archive, "manifest.plist").unwrap();
    
    let suggestion: Value = read_archive(&mut archive, "configuration/com.apple.posterkit.provider.identifierURL.suggestionMetadata.plist").unwrap_or(Value::Dictionary(Dictionary::new()));
    let complication: Value = read_archive(&mut archive, "configuration/versions/0/com.apple.posterkit.provider.instance.complicationLayout.plist").unwrap_or(Value::Dictionary(Dictionary::new()));
    let rendering: Value = read_archive(&mut archive, "configuration/versions/0/com.apple.posterkit.provider.instance.renderingConfiguration.plist").unwrap_or(Value::Dictionary(Dictionary::new()));
    
    
    // monogram/animoji
    let title_style: Value = read_archive(&mut archive, "configuration/versions/0/contents/com.apple.posterkit.provider.instance.titleStyleConfiguration.plist").unwrap_or(Value::Dictionary(Dictionary::new()));
    let user_info: Value = read_file(&mut archive, "configuration/versions/0/contents/com.apple.posterkit.provider.contents.userInfo").unwrap_or(Value::Dictionary(Dictionary::new()));
    
    
    // animoji
    let color_variations: Value = read_file(&mut archive, "configuration/versions/com.apple.posterkit.provider.instance.colorVariations.plist").unwrap_or(Value::Dictionary(Dictionary::new()));
    
    
    // image only
    let color_variations2: Value = read_archive(&mut archive, "configuration/versions/0/com.apple.posterkit.provider.instance.colorVariations.plist").unwrap_or(Value::Dictionary(Dictionary::new()));
    let titlestyle2: Value = read_archive(&mut archive, "configuration/versions/0/com.apple.posterkit.provider.instance.titleStyleConfiguration.plist").unwrap_or(Value::Dictionary(Dictionary::new()));
    let other_meta: Value = read_archive(&mut archive, "configuration/versions/0/contents/com.apple.posterkit.provider.contents.otherMetadata.plist").unwrap_or(Value::Dictionary(Dictionary::new()));
    let homescreen: Value = read_archive(&mut archive, "configuration/versions/0/supplements/0/com.apple.posterkit.provider.supplementURL.homescreenConfiguration.plist").unwrap_or(Value::Dictionary(Dictionary::new()));
    let model: Value = read_archive(&mut archive, "configuration/versions/0/contents/ConfigurationModel.plist").unwrap_or(Value::Dictionary(Dictionary::new()));
    let style: Value = read_file(&mut archive, "configuration/versions/0/contents/CB3D69CB-A1D0-4497-9105-9C6341A21BBB/style.plist").unwrap_or(Value::Dictionary(Dictionary::new()));

    let mut json = vec![];
    if let Ok(mut file) = archive.by_name("configuration/versions/0/contents/CB3D69CB-A1D0-4497-9105-9C6341A21BBB/output.layerStack/Contents.json") {
        file.read_to_end(&mut json).unwrap();
    }

    let mut end = Value::Dictionary(Dictionary::from_iter([
        ("meta", meta),
        ("manifest", manifest),
        ("suggestion", suggestion),
        ("complication", complication),
        ("rendering", rendering),
        ("homescreen", homescreen),
        ("other_meta", other_meta),
        ("model", model),
        ("json", Value::String(String::from_utf8(json).unwrap())),
        ("style", style),
        ("title_style", title_style),
        ("user_info", user_info),
        ("color_variations", color_variations),
        ("titlestyle2", titlestyle2),
        ("color_variations2", color_variations2),
    ]));
    sort_value(&mut end);
    debug!("Poster data {end:?}");

    Ok(plist_to_string(&end)?)
}


async fn handle_record(mut record: IMessageNicknameRecord, client: &IMClient, photo: &ProfilesClient<DefaultAnisetteProvider>, existing: &ShareProfileMessage) {
    if let Some(profile) = record.poster {
        let stamp = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
        fs::create_dir(format!("posters/{stamp}")).await.unwrap();
        let profile_2 = profile.clone();
        fs::write(format!("posters/{stamp}/image.heif"), profile.low_res_poster).await.unwrap();
        fs::write(format!("posters/{stamp}/data.zip"), profile.package).await.unwrap();
        fs::write(format!("posters/{stamp}/meta.plist"), profile.meta).await.unwrap();
        fs::write(format!("posters/{stamp}/file.plist"), parse_poster(&profile_2).unwrap()).await.unwrap();

        let mut to_poster = SimplifiedIncomingCallPoster::from_poster(&profile_2).unwrap();


        // let PosterType::Photo { assets } = &mut to_poster.r#type else { panic !()};

        // let contents = &mut assets[0].files;

        // contents.remove("portrait-layer_background.HEIC");
        // contents.insert("portrait-layer_background.HEIC".to_string(), fs::read("posters/photo_cropped_2/configuration/versions/0/contents/CB3D69CB-A1D0-4497-9105-9C6341A21BBB/output.layerStack/portrait-layer_background.jpg").await.unwrap());

        // let layer = assets[0].contents.layers.iter_mut().find(|l| l.identifier == "background").unwrap();
        // layer.filename = "portrait-layer_background.PNG".to_string();
        
        // contents.properties.portrait_layout.time_frame = PhotoPosterContentsFrame {
        //     width: 0f64,
        //     height: 0f64,
        //     x: 0f64,
        //     y: 0f64,
        // };

        // contents.properties.portrait_layout.inactive_frame = PhotoPosterContentsFrame {
        //     width: 0f64,
        //     height: 0f64,
        //     x: 0f64,
        //     y: 0f64,
        // };

        // contents.layers[0].frame.y += 200f64;
        // contents.properties.portrait_layout.visible_frame.y -= 200f64; // (slid viewport *DOWN* (could see further down image))

        to_poster.poster.r#type = PosterType::TranscriptDynamic { data: TranscriptDynamicUserData { identifier: "aurora_1".to_string() } };

        let by = to_poster.to_poster().unwrap();
        record.poster = Some(by);

        let mut existing = Some(existing.clone());
        photo.set_record(record, &mut existing).await.unwrap();

        client.send(&mut MessageInst::new(
            ConversationData { participants: vec!["mailto:tag3@copper.jjtech.dev".to_string()], cv_name: None, sender_guid: None, after_guid: None }, 
            "mailto:tag3@copper.jjtech.dev", Message::UpdateProfile(UpdateProfileMessage { profile: Some(existing.unwrap()), share_contacts: false }))).await.unwrap();
        
        // fs::write(format!("posters/{stamp}/poster.zip"), &by.package).await.unwrap();
    }
}

pub fn plist_to_buf<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, plist::Error> {
    let mut buf: Vec<u8> = Vec::new();
    let writer = Cursor::new(&mut buf);
    plist::to_writer_xml(writer, &value)?;
    Ok(buf)
}

pub fn plist_to_string<T: serde::Serialize>(value: &T) -> Result<String, plist::Error> {
    plist_to_buf(value).map(|val| String::from_utf8(val).unwrap())
}

async fn read_input() -> String {
    let stdin = io::stdin();
    let mut reader = BufReader::new(stdin);
    let mut username = String::new();
    reader.read_line(&mut username).await.unwrap();
    username
}

pub fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}

pub fn decode_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

const DEFAULT_RELAY_HOST: &str = "https://registration-relay.beeper.com";
const RELAY_TOKEN: &str = "5c175851953ecaf5209185d897591badb6c3e712";

struct RelaySettings {
    host: String,
    code: String,
}

const BPINDEX_SN: u8 = 0x10;
const BPINDEX_MAIN_ID: u8 = 0x11;
const BPINDEX_PUSH_TOKEN: u8 = 0x21;
const BPINDEX_PUSH_CERT: u8 = 0x22;
const BPINDEX_PUSH_KEY: u8 = 0x23;
const BPINDEX_ID_CERT: u8 = 0x31;
const BPINDEX_ID_PRIV_KEY: u8 = 0x32;
const BPINDEX_EC_PUB_KEY: u8 = 0x41;
const BPINDEX_EC_PRIV_KEY: u8 = 0x42;
const BPINDEX_RSA_PUB_KEY: u8 = 0x51;
const BPINDEX_RSA_PRIV_KEY: u8 = 0x52;

fn arg_value<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1)).map(|s| s.as_str())
}

fn has_flag(args: &[String], flag: &str) -> bool {
    args.iter().any(|a| a == flag)
}

fn flag_value(args: &[String], flag: &str) -> Option<String> {
    let prefix = format!("{flag}=");
    for arg in args {
        if let Some(value) = arg.strip_prefix(&prefix) {
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    arg_value(args, flag).map(|s| s.to_string())
}

fn relay_settings_from_args(args: &[String]) -> Result<RelaySettings, String> {
    let code = flag_value(args, "--relay-code")
        .or_else(|| std::env::var("RUSTPUSH_RELAY_CODE").ok())
        .ok_or_else(|| {
            "missing --relay-code=XXXX (pairing code from mac-registration-provider / registration-relay)".to_string()
        })?;
    let host = flag_value(args, "--relay-host")
        .or_else(|| std::env::var("RUSTPUSH_RELAY_HOST").ok())
        .unwrap_or_else(|| DEFAULT_RELAY_HOST.to_string());
    Ok(RelaySettings { host, code })
}

fn relay_settings_error(msg: &str) -> ! {
    eprintln!("{msg}");
    eprintln!("Example: ./rustpush-test --register --relay-code=ABCD-EFGH-IJKL-MNOP");
    eprintln!("Optional: --relay-host=https://your-registration-relay.example.com");
    std::process::exit(1);
}

fn append_bbox_tlv(out: &mut Vec<u8>, index: u8, value: &[u8]) {
    let len = value.len();
    assert!(len <= 0xffff, "BBOX value too large");
    out.push(index);
    out.push((len >> 8) as u8);
    out.push((len & 0xff) as u8);
    out.extend_from_slice(value);
}

fn wrap_identity_key(key: &[u8]) -> Vec<u8> {
    let len = key.len() as u16;
    [len.to_be_bytes().as_slice(), key].concat()
}

fn pem_to_der(pem: &[u8]) -> Result<Vec<u8>, PushError> {
    let text = std::str::from_utf8(pem).map_err(|_| PushError::BadMsg)?;
    let b64: String = text.lines().filter(|line| !line.starts_with("-----")).collect();
    general_purpose::STANDARD.decode(b64.trim()).map_err(|_| PushError::BadMsg)
}

#[derive(Serialize, Deserialize)]
struct GsaConfig {
    user: String,
    pass: Data,
}

fn rsa_private_pkcs1_der(der: &[u8]) -> Result<Vec<u8>, PushError> {
    // Keystore stores PKCS#8 DER; p-radar expects PKCS#1 DER when possible.
    let rsa = Rsa::private_key_from_der(der)?;
    let pem = rsa.private_key_to_pem()?;
    let text = std::str::from_utf8(&pem).map_err(|_| PushError::BadMsg)?;
    if text.contains("BEGIN RSA PRIVATE KEY") {
        pem_to_der(&pem)
    } else {
        Ok(der.to_vec())
    }
}

fn keystore_rsa_der(alias: &str) -> Result<Vec<u8>, PushError> {
    #[derive(Deserialize, Default)]
    struct KeystoreState {
        keys: HashMap<String, Data>,
    }
    let state: KeystoreState = plist::from_file("keystore.plist").map_err(|_| PushError::BadMsg)?;
    let entry = state.keys.get(alias).ok_or(PushError::BadMsg)?;
    let val: Value = plist::from_bytes(entry.as_ref()).map_err(|_| PushError::BadMsg)?;
    if let Value::Dictionary(dict) = val {
        if let Some(Value::Data(d)) = dict.get("Rsa") {
            let bytes: &[u8] = d.as_ref();
            return Ok(bytes.to_vec());
        }
    }
    Err(PushError::BadMsg)
}

fn legacy_keys_from_config() -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>), PushError> {
    let val: Value = plist::from_file("config.plist").map_err(|_| PushError::BadMsg)?;
    let legacy = val
        .as_dictionary()
        .and_then(|d| d.get("identity"))
        .and_then(|v| v.as_dictionary())
        .and_then(|d| d.get("legacy"))
        .and_then(|v| v.as_dictionary())
        .ok_or(PushError::BadMsg)?;
    let ec_priv = legacy
        .get("signing_key")
        .and_then(|v| v.as_data())
        .ok_or(PushError::BadMsg)?
        .as_ref()
        .to_vec();
    let rsa_priv = legacy
        .get("encryption_key")
        .and_then(|v| v.as_data())
        .ok_or(PushError::BadMsg)?
        .as_ref()
        .to_vec();

    let ec_key = EcKey::private_key_from_der(&ec_priv)?;
    let mut ctx = BigNumContext::new()?;
    let ec_pub = ec_key.public_key().to_bytes(
        ec_key.group(),
        PointConversionForm::UNCOMPRESSED,
        &mut ctx,
    )?;

    let rsa_key = Rsa::private_key_from_der(&rsa_priv)?;
    let rsa_pub = rsa_key.public_key_to_der_pkcs1()?;

    Ok((
        wrap_identity_key(&ec_pub),
        ec_priv,
        wrap_identity_key(&rsa_pub),
        rsa_priv,
    ))
}

fn primary_email(user: &IDSUser) -> Option<String> {
    for reg in user.registration.values() {
        for handle in &reg.handles {
            if let Some(email) = handle.strip_prefix("mailto:") {
                return Some(email.to_string());
            }
        }
    }
    None
}

fn build_bbox(serial: &str, main_id: &str, state: &SavedState) -> Result<String, PushError> {
    let push = &state.push;
    let user = &state.users[0];
    let token = push.token.as_ref().ok_or(PushError::TokenMissing)?;
    let keypair = push.keypair.as_ref().ok_or(PushError::TokenMissing)?;

    let push_key = rsa_private_pkcs1_der(&keystore_rsa_der(&keypair.private.0)?)?;
    let id_key = rsa_private_pkcs1_der(&keystore_rsa_der(&user.auth_keypair.private.0)?)?;
    let id_rsa = Rsa::private_key_from_der(&id_key)?;
    let id_rsa_pub = wrap_identity_key(&id_rsa.public_key_to_der_pkcs1()?);
    let (ec_pub, ec_priv, _, _) = legacy_keys_from_config()?;

    // id-query validates the short-lived madrid registration cert (the one whose
    // key signs the query), NOT the long-lived auth cert. They share the same RSA
    // key, so id_key above stays correct; only the cert slot must use the madrid cert.
    let id_cert = user
        .registration
        .get("com.apple.madrid")
        .map(|r| r.id_keypair.cert.clone())
        .unwrap_or_else(|| user.auth_keypair.cert.clone());

    let mut raw = Vec::new();
    append_bbox_tlv(&mut raw, BPINDEX_SN, serial.as_bytes());
    append_bbox_tlv(&mut raw, BPINDEX_MAIN_ID, main_id.as_bytes());
    append_bbox_tlv(&mut raw, BPINDEX_PUSH_TOKEN, token);
    append_bbox_tlv(&mut raw, BPINDEX_PUSH_CERT, &keypair.cert);
    append_bbox_tlv(&mut raw, BPINDEX_PUSH_KEY, &push_key);
    append_bbox_tlv(&mut raw, BPINDEX_ID_CERT, &id_cert);
    append_bbox_tlv(&mut raw, BPINDEX_ID_PRIV_KEY, &id_key);
    append_bbox_tlv(&mut raw, BPINDEX_EC_PUB_KEY, &ec_pub);
    append_bbox_tlv(&mut raw, BPINDEX_EC_PRIV_KEY, &ec_priv);
    // p-radar signHash uses 0x52; it must match 0x31 ID cert (same as 0x32), not legacy NGM key.
    append_bbox_tlv(&mut raw, BPINDEX_RSA_PUB_KEY, &id_rsa_pub);
    append_bbox_tlv(&mut raw, BPINDEX_RSA_PRIV_KEY, &id_key);

    Ok(general_purpose::STANDARD.encode(raw))
}

async fn load_bbox_serial(args: &[String]) -> Result<String, PushError> {
    if let Some(serial) = flag_value(args, "--serial") {
        return Ok(serial);
    }
    let config = resolve_relay_config(args, false).await;
    Ok(config.get_serial_number())
}

async fn export_bbox_with_relay_defaults() {
    let args: Vec<String> = std::env::args().collect();
    let output = flag_value(&args, "--output").unwrap_or_else(|| "caches.json".to_string());

    let _ = resolve_relay_config(&args, false).await;

    init_keystore(SoftwareKeystore {
        state: plist::from_file("keystore.plist").unwrap_or_default(),
        update_state: Box::new(|state| {
            plist::to_file_xml("keystore.plist", state).unwrap();
        }),
        encryptor: NoEncryptor,
    });

    let saved: SavedState = match plist::from_file("config.plist") {
        Ok(v) => v,
        Err(e) => {
            eprintln!("BBOX export failed: cannot read config.plist: {e}");
            std::process::exit(1);
        }
    };
    if saved.users.is_empty() {
        eprintln!("BBOX export failed: config.plist has no users");
        std::process::exit(1);
    }

    let serial = match load_bbox_serial(&args).await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("BBOX export failed: {e}");
            std::process::exit(1);
        }
    };
    let main_id = flag_value(&args, "--main-id")
        .or_else(|| primary_email(&saved.users[0]))
        .or_else(|| plist::from_file::<_, GsaConfig>("gsa.plist").ok().map(|g| g.user));
    let main_id = match main_id {
        Some(v) => v,
        None => {
            eprintln!("BBOX export failed: could not determine Apple ID email");
            std::process::exit(1);
        }
    };

    match build_bbox(&serial, &main_id, &saved) {
        Ok(bbox) => {
            let json = serde_json::to_string_pretty(&vec![bbox]).unwrap();
            fs::write(&output, json).await.expect("failed to write output");
            println!("Wrote {} (1 entry)", output);
            println!("Serial: {serial}");
            println!("Main ID: {main_id}");
        }
        Err(e) => {
            eprintln!("BBOX export failed: {e}");
            std::process::exit(1);
        }
    }
}

fn lookup_error_code(err: &PushError) -> Option<u64> {
    match err {
        PushError::LookupFailed(code) => Some(code.0),
        PushError::DoNotRetry(inner) => lookup_error_code(inner),
        _ => None,
    }
}

fn format_lookup_target(raw: &str) -> String {
    let raw = raw.trim();
    if raw.contains(':') {
        raw.to_string()
    } else if raw.contains('@') {
        format!("mailto:{raw}")
    } else {
        format!("tel:{raw}")
    }
}

fn collect_lookup_targets(args: &[String]) -> Vec<String> {
    let mut targets = Vec::new();
    let mut i = 2;
    while i < args.len() {
        if args[i] == "--target" {
            if let Some(t) = args.get(i + 1) {
                targets.push(format_lookup_target(t));
                i += 2;
                continue;
            }
        } else if !args[i].starts_with('-') {
            targets.push(format_lookup_target(&args[i]));
        }
        i += 1;
    }
    if targets.is_empty() {
        targets.push(format_lookup_target("mailto:hilmi.azizi19@icloud.com"));
    }
    targets
}

fn lookup_plists_ready() -> bool {
    for path in ["config.plist", "hwconfig.plist", "keystore.plist"] {
        if !Path::new(path).exists() {
            return false;
        }
    }
    let Ok(saved) = plist::from_file::<_, SavedState>("config.plist") else {
        return false;
    };
    !saved.users.is_empty() && !saved.users[0].registration.is_empty()
}

async fn run_lookup_from_plists() {
    init_keystore(SoftwareKeystore {
        state: plist::from_file("keystore.plist").unwrap_or_default(),
        update_state: Box::new(|state| {
            plist::to_file_xml("keystore.plist", state).unwrap();
        }),
        encryptor: NoEncryptor,
    });

    let saved_state: SavedState = plist::from_file("config.plist")
        .expect("config.plist missing or invalid SavedState");
    let config: Arc<RelayConfig> = Arc::new(
        plist::from_file("hwconfig.plist").expect("hwconfig.plist missing or invalid RelayConfig"),
    );

    info!("Fast lookup: using cached plists (skipping relay, GSA login, and registration)");

    let state: Arc<Mutex<Option<SavedState>>> = Arc::new(Mutex::new(Some(saved_state.clone())));
    let (connection, error) = APSConnectionResource::new(
        config.clone(),
        Some(saved_state.push.clone()),
    )
    .await;

    if let Some(error) = error {
        panic!("{}", error);
    }

    let services = &[&MADRID_SERVICE, &MULTIPLEX_SERVICE, &FACETIME_SERVICE, &VIDEO_SERVICE];
    let state_for_client = state.clone();
    let client = IMClient::new(
        connection.clone(),
        saved_state.users,
        saved_state.identity,
        services,
        "id_cache.plist".into(),
        config.clone(),
        Box::new(move |updated_keys| {
            if let Some(saved) = state_for_client.lock().unwrap().as_mut() {
                saved.users = updated_keys;
                std::fs::write(
                    "config.plist",
                    plist_to_string(saved).unwrap(),
                )
                .unwrap();
            }
        }),
    )
    .await;

    let handle = client.identity.get_handles().await[0].clone();
    test_ids_lookup(&client, &handle).await;

    // Drop client before APS so topic interest tokens unregister cleanly.
    drop(client);
    drop(connection);
}

async fn test_ids_lookup(client: &IMClient, handle: &str) {
    let args: Vec<String> = std::env::args().collect();
    let targets = collect_lookup_targets(&args);

    info!("IDS id-query test (same API p-radar uses, via APNs)");
    info!("  self handle: {handle}");
    info!("  targets ({}): {targets:?}", targets.len());

    match client
        .identity
        .validate_targets(&targets, MADRID_SERVICE.name, handle)
        .await
    {
        Ok(valid) => {
            println!("LOOKUP OK");
            println!("  self: {handle}");
            println!("  queried: {targets:?}");
            println!("  valid: {valid:?}");
        }
        Err(err) => {
            if let Some(code) = lookup_error_code(&err) {
                println!("LOOKUP FAILED status={code}");
                println!("  (p-radar prints this as QUERY-ERROR:{code})");
            } else {
                println!("LOOKUP ERROR: {err}");
            }
            std::process::exit(1);
        }
    }
}

async fn relay_config(settings: &RelaySettings) -> Arc<RelayConfig> {
    let token = Some(RELAY_TOKEN.to_string());
    info!(
        "Fetching relay version info from {} (code {})",
        settings.host, settings.code
    );
    let version = RelayConfig::get_versions(&settings.host, &settings.code, &token)
        .await
        .unwrap();
    let icloud_ua = version.icloud_user_agent();
    Arc::new(RelayConfig {
        version,
        icloud_ua,
        aoskit_version: "com.apple.AOSKit/282 (com.apple.accountsd/113)".to_string(),
        dev_uuid: Uuid::new_v4().to_string(),
        protocol_version: 1640,
        host: settings.host.clone(),
        code: settings.code.clone(),
        beeper_token: token,
        udid: None,
    })
}

/// Prove a freshly-paired relay can mint validation-data on demand. This is the
/// linchpin of iPhone-free renewal: registration/renewal needs exactly one
/// device-bound input (validation-data) and everything else lives in our own
/// persisted keys. If this succeeds, the relay can keep a fleet of identities
/// alive without the phone being in the loop for anything else.
async fn run_relay_test() {
    let args: Vec<String> = std::env::args().collect();
    let settings = match relay_settings_from_args(&args) {
        Ok(s) => s,
        Err(msg) => relay_settings_error(&msg),
    };

    let token = Some(RELAY_TOKEN.to_string());
    info!(
        "Relay test: fetching version info from {} (code {})",
        settings.host, settings.code
    );
    let version = match RelayConfig::get_versions(&settings.host, &settings.code, &token).await {
        Ok(v) => v,
        Err(e) => {
            error!("relay get-version-info FAILED: {e}");
            eprintln!("\nRelay/provider unreachable or the code is wrong/expired.");
            eprintln!("Make sure the mobile provider is still paired and online.");
            std::process::exit(1);
        }
    };

    let icloud_ua = version.icloud_user_agent();
    let config = RelayConfig {
        version,
        icloud_ua,
        aoskit_version: "com.apple.AOSKit/282 (com.apple.accountsd/113)".to_string(),
        dev_uuid: Uuid::new_v4().to_string(),
        protocol_version: 1640,
        host: settings.host.clone(),
        code: settings.code.clone(),
        beeper_token: token,
        udid: None,
    };

    let meta = config.get_register_meta();
    println!("\n=== relay hardware identity (what validation-data is bound to) ===");
    println!("  model  : {}", meta.hardware_version);
    println!("  os     : {}", meta.os_version);
    println!("  serial : {}", config.get_serial_number());
    println!("  udid   : {}", config.get_udid());
    println!("  ua     : {}", config.get_version_ua());

    println!("\n=== minting validation-data (twice, to prove it is live) ===");
    for i in 1..=2 {
        match config.generate_validation_data().await {
            Ok(data) => {
                let b64 = base64_encode(&data);
                let prefix: String = b64.chars().take(40).collect();
                println!("  attempt {i}: OK  {} bytes  b64={}...", data.len(), prefix);
            }
            Err(e) => {
                error!("generate_validation_data attempt {i} FAILED: {e}");
                eprintln!("\nProvider answered version-info but cannot mint validation-data.");
                std::process::exit(1);
            }
        }
    }

    fs::write("hwconfig.plist", plist_to_string(&config).unwrap())
        .await
        .unwrap();
    println!(
        "\nSaved hwconfig.plist (serial {}). Relay is a working validation-data source.",
        config.get_serial_number()
    );
}

async fn resolve_relay_config(args: &[String], force_relay_fetch: bool) -> Arc<RelayConfig> {
    if !force_relay_fetch && Path::new("hwconfig.plist").exists() {
        if let Ok(config) = plist::from_file::<_, RelayConfig>("hwconfig.plist") {
            info!(
                "Using cached hwconfig.plist (serial {})",
                config.get_serial_number()
            );
            return Arc::new(config);
        }
    }
    let settings = match relay_settings_from_args(args) {
        Ok(s) => s,
        Err(msg) => relay_settings_error(&msg),
    };
    let config = relay_config(&settings).await;
    fs::write("hwconfig.plist", plist_to_string(config.as_ref()).unwrap())
        .await
        .unwrap();
    info!(
        "Saved hwconfig.plist (serial {})",
        config.get_serial_number()
    );
    config
}

fn format_delegate_login_error(err: &PushError) -> String {
    match err {
        PushError::UnauthorizedAccountError => {
            "setup.icloud.com returned UNAUTHORIZED (see WARN lines above for raw plist). \
             GSA login succeeded; this is delegate/device validation, not securityUpgrade/2FA."
                .to_string()
        }
        PushError::MobileMeError(code, desc) => format!("setup.icloud.com MobileMeError: {code} ({desc:?})"),
        PushError::AuthError(v) => format!("setup.icloud.com AuthError: {v:?}"),
        PushError::DelegateLoginFailed(delegate, status, msg) => {
            format!("delegate {delegate} failed status={status} msg={msg}")
        }
        other => format!("{other}"),
    }
}

/// Pick one bbox out of a file that may be a JSON array of base64 strings
/// (like `caches_sample.json`) or a single base64 blob (like `sample1.json`).
fn pick_bbox(raw: &str, index: usize) -> String {
    if let Ok(list) = serde_json::from_str::<Vec<String>>(raw) {
        return list
            .get(index)
            .cloned()
            .unwrap_or_else(|| panic!("bbox index {index} out of range ({} total)", list.len()));
    }
    raw.trim().to_string()
}

/// User-agent for the madrid-lookup request. Mirrors the relay's OS when a
/// cached hwconfig.plist is available, otherwise a sane macOS default.
fn bbox_version_ua() -> String {
    if let Ok(cfg) = plist::from_file::<_, RelayConfig>("hwconfig.plist") {
        return cfg.get_version_ua();
    }
    "[macOS,13.6.1,22G313,iMac19,1]".to_string()
}

/// Smoke test: load a bbox and run a single pure-HTTP id-query lookup.
async fn run_bbox_lookup() {
    init_keystore(SoftwareKeystore {
        state: Default::default(),
        update_state: Box::new(|_| {}),
        encryptor: NoEncryptor,
    });

    let args: Vec<String> = std::env::args().collect();
    let path = flag_value(&args, "--bbox-file").unwrap_or_else(|| "caches_sample.json".to_string());
    let index: usize = flag_value(&args, "--bbox-index")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read bbox file {path}: {e}"));
    let b64 = pick_bbox(&raw, index);

    let bbox = Bbox::parse_b64(&b64).expect("failed to parse bbox");
    info!(
        "bbox loaded: serial={} self_uri={} service={}",
        bbox.serial, bbox.self_uri, bbox.service
    );

    let id_keypair = bbox.id_keypair().expect("failed to import bbox identity key");
    let targets = collect_lookup_targets(&args);
    let version_ua = bbox_version_ua();

    info!(
        "pure-HTTP id-query: {} target(s), ua={version_ua}",
        targets.len()
    );

    let response = match bbox_id_query_raw(
        &id_keypair,
        &bbox.push_token,
        &bbox.self_uri,
        &bbox.service,
        1640,
        &version_ua,
        &targets,
    )
    .await
    {
        Ok(v) => v,
        Err(e) => {
            println!("LOOKUP FAILED: {e}");
            std::process::exit(1);
        }
    };

    print_lookup_summary(&response, &targets);
}

/// Pull printable ASCII runs (>= 3 chars) out of a binary blob, mirroring the
/// kt-account-key string extraction in reverse/response.json.
fn ascii_strings(data: &[u8], min_len: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for &b in data {
        if (0x20..0x7f).contains(&b) {
            cur.push(b as char);
        } else {
            if cur.len() >= min_len {
                out.push(std::mem::take(&mut cur));
            } else {
                cur.clear();
            }
        }
    }
    if cur.len() >= min_len {
        out.push(cur);
    }
    out
}

fn dict_get<'a>(d: &'a Value, key: &str) -> Option<&'a Value> {
    d.as_dictionary().and_then(|d| d.get(key))
}

fn as_bool(v: Option<&Value>) -> bool {
    v.and_then(|v| v.as_boolean()).unwrap_or(false)
}

fn as_int(v: Option<&Value>) -> Option<i64> {
    v.and_then(|v| v.as_signed_integer())
}

/// Numeric value that may come back from IDS as either an integer or a real.
/// Formatted without a trailing `.0` when it's a whole number.
fn as_num_str(v: Option<&Value>) -> String {
    let n = v.and_then(|v| {
        v.as_signed_integer()
            .map(|i| i as f64)
            .or_else(|| v.as_real())
    });
    match n {
        Some(x) if x.fract() == 0.0 => format!("{}", x as i64),
        Some(x) => format!("{x}"),
        None => "-".to_string(),
    }
}

/// Parse a raw IDS id-query response into a human-readable report and print it.
/// Field mapping follows reverse/response.json.
fn print_lookup_summary(response: &Value, targets: &[String]) {
    let status = as_int(dict_get(response, "status")).unwrap_or(-1);
    let empty = plist::Dictionary::new();
    let results = dict_get(response, "results")
        .and_then(|v| v.as_dictionary())
        .unwrap_or(&empty);

    let registered: Vec<&String> = targets
        .iter()
        .filter(|t| {
            results
                .get(*t)
                .and_then(|u| dict_get(u, "identities"))
                .and_then(|i| i.as_array())
                .map(|a| !a.is_empty())
                .unwrap_or(false)
        })
        .collect();

    println!("============================================================");
    println!("IDS id-query response   query_status={status}");
    println!(
        "targets={}   on_iMessage={}",
        targets.len(),
        registered.len()
    );
    println!("============================================================");

    for uri in targets {
        let Some(entry) = results.get(uri) else {
            println!("\n{uri}\n   (no result returned)");
            continue;
        };

        let identities = dict_get(entry, "identities")
            .and_then(|i| i.as_array())
            .cloned()
            .unwrap_or_default();
        let per_status = as_int(dict_get(entry, "status")).unwrap_or(0);
        let reg = !identities.is_empty();

        println!(
            "\n{uri}   {}   ({} device{})",
            if reg { "REGISTERED" } else { "NOT registered" },
            identities.len(),
            if identities.len() == 1 { "" } else { "s" }
        );
        if per_status != 0 {
            println!("   status: {per_status}");
        }

        if let Some(scid) = dict_get(entry, "sender-correlation-identifier").and_then(|v| v.as_string()) {
            println!("   sender-correlation: {scid}");
        }
        if let Some(sh) = dict_get(entry, "short-handle").and_then(|v| v.as_string()) {
            println!("   short-handle: {sh}");
        }
        if let Some(kt) = dict_get(entry, "kt-account-key").and_then(|v| v.as_data()) {
            let strings = ascii_strings(kt, 3);
            if !strings.is_empty() {
                println!("   kt-account-key: [{}]", strings.join(", "));
            }
        }

        for (idx, ident) in identities.iter().enumerate() {
            let token_hex = dict_get(ident, "push-token")
                .and_then(|v| v.as_data())
                .map(|d| d.iter().map(|b| format!("{b:02x}")).collect::<String>())
                .unwrap_or_default();
            let cd = dict_get(ident, "client-data");
            let ngm = as_num_str(cd.and_then(|c| dict_get(c, "public-message-identity-ngm-version")));
            let idv = as_num_str(cd.and_then(|c| dict_get(c, "public-message-identity-version")));
            let certified = cd.map(|c| as_bool(dict_get(c, "supports-certified-delivery-v1"))).unwrap_or(false);
            let hdr = cd.map(|c| as_bool(dict_get(c, "supports-hdr"))).unwrap_or(false);
            let stewie = cd.map(|c| as_bool(dict_get(c, "supports-stewie"))).unwrap_or(false);

            println!(
                "   device {}: push={token_hex}",
                idx + 1
            );
            println!(
                "            ngm={ngm} idv={idv} certified={} hdr={} stewie/satellite={}",
                yn(certified), yn(hdr), yn(stewie)
            );
        }
    }
    println!();
}

fn yn(b: bool) -> &'static str {
    if b { "yes" } else { "no" }
}

#[tokio::main(worker_threads = 1)]
async fn main() {
    if let Err(_) = std::env::var("RUST_LOG") {
        std::env::set_var("RUST_LOG", "debug");
    }
    pretty_env_logger::try_init().unwrap();

    let args: Vec<String> = std::env::args().collect();
    let register_only = has_flag(&args, "--register");
    let test_lookup = has_flag(&args, "--test-lookup");

    if has_flag(&args, "--export-bbox") {
        export_bbox_with_relay_defaults().await;
        return;
    }

    if has_flag(&args, "--bbox-lookup") {
        run_bbox_lookup().await;
        return;
    }

    if has_flag(&args, "--relay-test") {
        run_relay_test().await;
        return;
    }

    if test_lookup && lookup_plists_ready() {
        run_lookup_from_plists().await;
        return;
    }

    if register_only && flag_value(&args, "--relay-code").is_none() {
        relay_settings_error(
            "missing --relay-code=... (--register always fetches a fresh relay identity)",
        );
    }

    // let record = IMessagePosterRecord {
    //     low_res_poster: fs::read("posters/image_style_plain/image.png").await.unwrap(),
    //     package: fs::read("posters/image_style_plain/data.zip").await.unwrap(),
    //     meta: fs::read("posters/image_style_plain/meta.plist").await.unwrap(),
    // };
    

    // panic!();

    // debug!("item {}", plist_to_string(&IDSUserIdentity::new().unwrap()).unwrap());

    // info!("here {}", get_gateways_for_mccmnc("310160").await.unwrap());

    init_keystore(SoftwareKeystore {
        state: plist::from_file("keystore.plist").unwrap_or_default(),
        update_state: Box::new(|state| {
            plist::to_file_xml("keystore.plist", state).unwrap();
        }),
        encryptor: NoEncryptor,
    });


    let data: String = match fs::read_to_string("config.plist").await {
		Ok(v) => v,
		Err(e) => {
			match e.kind() {
				io::ErrorKind::NotFound => {
					let _ = fs::File::create("config.plist").await.expect("Unable to create file").write_all(b"{}");
					"{}".to_string()
				}
				_ => {
				    error!("Unable to read file");
					std::process::exit(1);
				}
			}
		}
	};

    let gsa: GsaConfig = if let Ok(config) = plist::from_file("gsa.plist") {
        config
    } else {
        print!("Username: ");
        std::io::stdout().flush().unwrap();
        let username = read_input().await;
        print!("Password: ");
        std::io::stdout().flush().unwrap();
        let password = read_input().await;

        GsaConfig { user: username.trim().to_string(), pass: sha256(password.trim().as_bytes()).to_vec().into() }
    };

    plist::to_file_xml("gsa.plist", &gsa).unwrap();
    
    
    
    // let config: Arc<MacOSConfig> = Arc::new(if let Ok(config) =
    // plist::from_file("hwconfig.plist") {
    //     config
    // } else {
    //     println!("Missing hardware config!");
    //     println!("The easiest way to get your hardware config is to extract it from validation data from a Mac.");
    //     println!("This validation data will not be used to authenticate, and therefore does not need to be recent or valid.");
    //     println!("If you need help obtaining validation data, please visit https://github.com/beeper/mac-registration-provider");
    //     println!("As long as the hardware identifiers are valid rustpush will work fine.");
    //     println!("Validation data will not be required for subsequent re-registrations.");
    //     // save hardware config
    //     print!("Validation data: ");
    //     std::io::stdout().flush().unwrap();
    //     let validation_data_b64 = read_input().await;
    //
    //     let validation_data = general_purpose::STANDARD.decode(validation_data_b64.trim()).unwrap();
    //     let extracted = HardwareConfig::from_validation_data(&validation_data).unwrap();
    //
    //     MacOSConfig {
    //         inner: extracted,
    //         version: "13.6.4".to_string(),
    //         protocol_version: 1660,
    //         device_id: Uuid::new_v4().to_string(),
    //         icloud_ua: "com.apple.iCloudHelper/282 CFNetwork/1408.0.4 Darwin/22.5.0".to_string(),
    //         aoskit_version: "com.apple.AOSKit/282 (com.apple.accountsd/113)".to_string(),
    //         udid: Some("55A1CFBF5BB56AD1159BD2CB7D6FF546E48EAAE4BF16188A07B1FB9C83138CA2".to_string()),
    //     }
    // });
    let config = resolve_relay_config(&args, register_only).await;

    let saved_state: Option<SavedState> = plist::from_reader_xml(Cursor::new(&data)).ok();
    // let saved_state: Option<SavedState> = None;

    let state: Arc<Mutex<Option<SavedState>>> = Arc::new(Mutex::new(None));
    let (connection, error) = 
        APSConnectionResource::new(
            config.clone(),
            saved_state.as_ref().map(|state| state.push.clone()),
        )
        .await;

    let mut subscription = connection.messages_cont.subscribe();

    let mut anisette_client = default_provider(config.get_gsa_config(&*connection.state.read().await, false), PathBuf::from_str("anisette_test").unwrap());

    let mut session: Option<CircleClientSession<DefaultAnisetteProvider>> = None;
    
    if let Some(error) = error {
        panic!("{}", error);
    }
    let mut users = if let Some(state) = saved_state.as_ref() {
        state.users.clone()
    } else {
        let mut account = AppleAccount::new_with_anisette(config.get_gsa_config(&*connection.state.read().await, false), anisette_client.clone()).unwrap();
        let mut login_state = account.login_email_pass(&gsa.user, gsa.pass.as_ref()).await.unwrap();

        loop {
            login_state = match login_state {
                LoginState::NeedsSMS2FA => {
                    let extras = account.get_auth_extras().await.unwrap();
                    if let Some(state @ LoginState::NeedsSMS2FAVerification(_)) = extras.new_state {
                        println!("A verification SMS has been sent to your trusted phone number.");
                        state
                    } else if let Some(phone) = extras.trusted_phone_numbers.first() {
                        println!(
                            "Sending verification SMS to {} (ends in {})...",
                            phone.number_with_dial_code, phone.last_two_digits
                        );
                        account.send_sms_2fa_to_devices(phone.id).await.unwrap()
                    } else {
                        panic!("No trusted phone numbers on this Apple ID");
                    }
                }
                LoginState::NeedsSMS2FAVerification(body) => {
                    print!("Enter the 6-digit code from the SMS: ");
                    std::io::stdout().flush().unwrap();
                    let mut input = String::new();
                    std::io::stdin().read_line(&mut input).unwrap();
                    account.verify_sms_2fa(input.trim().to_string(), body).await.unwrap()
                }
                LoginState::Needs2FAVerification => {
                    print!("Enter the 6-digit verification code: ");
                    std::io::stdout().flush().unwrap();
                    let mut input = String::new();
                    std::io::stdin().read_line(&mut input).unwrap();
                    account.verify_2fa(input.trim().to_string()).await.unwrap()
                }
                LoginState::NeedsDevice2FA => {
                    println!("Apple requires two-factor authentication for this account.");
                    println!("  1 = Send SMS code (recommended)");
                    println!("  2 = Show code on a trusted iPhone/Mac");
                    println!("  3 = Wait for sign-in approval here (often unreliable on Linux)");
                    print!("Choose [1]: ");
                    std::io::stdout().flush().unwrap();
                    let mut choice = String::new();
                    std::io::stdin().read_line(&mut choice).unwrap();
                    match choice.trim() {
                        "2" | "push" => account.send_2fa_to_devices().await.unwrap(),
                        "3" | "circle" => break,
                        _ => {
                            let extras = account.get_auth_extras().await.unwrap();
                            if let Some(state @ LoginState::NeedsSMS2FAVerification(_)) = extras.new_state {
                                println!("A verification SMS has been sent to your trusted phone number.");
                                state
                            } else if let Some(phone) = extras.trusted_phone_numbers.first() {
                                println!(
                                    "Sending verification SMS to {} (ends in {})...",
                                    phone.number_with_dial_code, phone.last_two_digits
                                );
                                account.send_sms_2fa_to_devices(phone.id).await.unwrap()
                            } else {
                                panic!("No trusted phone numbers on this Apple ID — try option 2 or 3");
                            }
                        }
                    }
                }
                LoginState::LoggedIn => break,
                LoginState::NeedsExtraStep(ref step) => {
                    println!("Ignoring optional Apple ID step: {}", step);
                    break;
                }
                other => panic!("Unexpected login state: {:?}", other),
            }
        }

        let spd = account.spd.as_ref().unwrap();
        let dsid = spd["DsPrsId"].as_unsigned_integer().unwrap();

        let done = Arc::new(DebugMutex::new(account));

        if matches!(login_state, LoginState::NeedsDevice2FA) {
            let mut s = CircleClientSession::new(dsid, done.clone(), connection.get_token().await).await.unwrap();

            let listener = IdmsAuthListener::new(connection.clone()).await;
            let mut subscription = connection.messages_cont.subscribe();

            println!("Waiting for Apple sign-in — approve on your iPhone/Mac, then enter the code when prompted.");
            println!("If nothing appears within ~30s, press Ctrl+C and rerun; choose option 1 (SMS) instead.");
            std::io::stdout().flush().unwrap();

            loop {
                let msg = subscription.recv().await.unwrap();

                if let Some(test) = listener.handle(msg.clone()).unwrap() {
                    info!("here {test:?}");
                    match test {
                        IdmsMessage::TeardownSignIn(_) => info!("Teardown sign in"),
                        IdmsMessage::RequestedSignIn(_) => info!("requested sign in code {}", anisette_client.lock().await.provider.get_2fa_code().await.unwrap()),
                        IdmsMessage::CircleRequest(c, _) => {
                            if c.step == 2 {
                                print!("Enter the 6-digit verification code shown on your trusted device: ");
                                std::io::stdout().flush().unwrap();
                                let mut input = String::new();
                                std::io::stdin().read_line(&mut input).unwrap();
                                s.send_code(input.trim()).await.unwrap();
                            }
                            if s.handle_circle_request(&c).await.unwrap().is_some() {
                                session = Some(s);
                                break;
                            }
                        }
                    }
                }
            }
        }

        let account = done.lock().await;

        // account.update_postdata("Testing").await.unwrap();
        account.get_delegate_password().expect("Login succeeded but no delegate token was returned");
        let spd = account.spd.as_ref().unwrap();

        // Delegate login. Burner / never-set-up accounts gate ALL delegates (even IDS) behind
        // MOBILEME_TERMS_OF_SERVICE_UPDATE — the error is returned at the TOP LEVEL of the
        // setup.icloud.com login, so requesting IDS-only does NOT avoid it. Auto-accept the
        // iCloud ToS: first via the lightweight `termsAccepted=true` cookie, then by fetching
        // the terms UI and POSTing its agreeUrl.
        let delegate_list: &[LoginDelegate] = &[LoginDelegate::IDS, LoginDelegate::MobileMe];
        let delegates = match login_apple_delegates(&account, None, config.as_ref(), delegate_list).await {
            Err(PushError::MobileMeError(code, _)) if code == "MOBILEME_TERMS_OF_SERVICE_UPDATE" => {
                info!("Accepting iCloud Terms of Service...");
                match login_apple_delegates(&account, Some("termsAccepted=true"), config.as_ref(), delegate_list).await {
                    Ok(delegates) => delegates,
                    Err(PushError::MobileMeError(code, _)) if code == "MOBILEME_TERMS_OF_SERVICE_UPDATE" => {
                        let (_, finish) = request_update_account(&account, config.as_ref()).await.unwrap();
                        finish.accept_terms(delegate_list, &account, config.as_ref()).await.unwrap()
                    }
                    Err(err) => {
                        eprintln!("Delegate login failed after ToS retry: {}", format_delegate_login_error(&err));
                        std::process::exit(1);
                    }
                }
            }
            Err(err) => {
                eprintln!("Delegate login failed: {}", format_delegate_login_error(&err));
                std::process::exit(1);
            }
            Ok(delegates) => delegates,
        };
        let user = authenticate_apple(delegates.ids.unwrap(), config.as_ref()).await.unwrap();

        let findmy = FindMyState::new(spd["DsPrsId"].as_unsigned_integer().unwrap().to_string());

        let id_path = PathBuf::from_str("findmy.plist").unwrap();
        std::fs::write(id_path, findmy.encode().unwrap()).unwrap();

        let cloudkitstate = CloudKitState::new(spd["DsPrsId"].as_unsigned_integer().unwrap().to_string());
        let id_path = PathBuf::from_str("cloudkit.plist").unwrap();
        std::fs::write(id_path, plist_to_string(&cloudkitstate).unwrap()).unwrap();

        // iCloud-only state needs the MobileMe delegate; skip when unavailable (VM).
        if let Some(mobileme) = delegates.mobileme {
            let sharedstreams = SharedStreamsState::new(spd["DsPrsId"].as_unsigned_integer().unwrap().to_string(), &mobileme);
            let id_path = PathBuf::from_str("sharedstreams.plist").unwrap();
            std::fs::write(id_path, plist_to_string(&sharedstreams).unwrap()).unwrap();

            let trustedpeers = KeychainClientState::new(spd["DsPrsId"].as_unsigned_integer().unwrap().to_string(), spd["adsid"].as_string().unwrap().to_string(), &mobileme);
            let id_path = PathBuf::from_str("trustedpeers.plist").unwrap();
            std::fs::write(id_path, plist_to_string(&trustedpeers).unwrap()).unwrap();
        }

        vec![user]
    };

    // TODO DO NOT COMMIT
    let conf = (gsa.user.clone(), gsa.pass.as_ref().to_vec());
    let appleid_closure = move || conf.clone();
        // ask console for 2fa code, make sure it is only 6 digits, no extra characters
        let tfa_closure = || {
            println!("Enter 2FA code: ");
            let mut input = String::new();
            std::io::stdin().read_line(&mut input).unwrap();
            input.trim().to_string()
        };

    let acc = AppleAccount::login(appleid_closure, tfa_closure, 
        config.get_gsa_config(&*connection.state.read().await, false), anisette_client.clone()).await;
    

    // let mut entitlementstate = EntitlementAuthState::new("0310260600163417@nai.epc.mnc260.mcc310.3gppnetwork.org".to_string(), "310260".to_string(), "358565077172633".to_string());

    // let entitlementresult = entitlementstate.get_entitlements(config.as_ref(), &connection, |challenge| async move {
    //     #[derive(Deserialize)]
    //     struct Response {
    //         response: String,
    //     }

    //     let result: Response = reqwest::Client::new()
    //         .post("http://192.168.99.200:8080/eap_aka")
    //         .json(&json!({
    //             "challenge": challenge
    //         }))
    //         .send().await?
    //         .json().await?;
    //     Ok(result.response)
    // }).await.expect("Failed to get entitlements");
    
    // authenticate_smsless(&entitlementresult.phone, &entitlementresult.host, config.as_ref(), &connection).await.unwrap();

    // panic!("test {:?}", entitlementresult.phone);


    let account = Arc::new(DebugMutex::new(acc.unwrap()));
    
    account.lock().await.update_postdata("Apple Device", None, &["icloud", "imessage", "facetime"]).await.unwrap();

    let services = &[&MADRID_SERVICE, &MULTIPLEX_SERVICE, &FACETIME_SERVICE, &VIDEO_SERVICE];

    let identity = saved_state.as_ref().map(|state| state.identity.clone()).unwrap_or(IDSNGMIdentity::new().unwrap());

    if users[0].registration.is_empty() || register_only {
        info!("Registering identity with relay...");
        register(config.as_ref(), &*connection.state.read().await, services, &mut users, &identity).await.unwrap();
    }

    *state.lock().unwrap() = Some(SavedState {
        push: connection.state.read().await.clone(),
        identity: identity.clone(),
        users: users.clone()
    });
    fs::write("config.plist", plist_to_string(state.lock().unwrap().as_ref().unwrap()).unwrap()).await.unwrap();
    info!("Credentials saved to config.plist");

    let client = IMClient::new(connection.clone(), users, identity, services, "id_cache.plist".into(), config.clone(), Box::new(move |updated_keys| {
        state.lock().unwrap().as_mut().unwrap().users = updated_keys;
        std::fs::write("config.plist", plist_to_string(state.lock().unwrap().as_ref().unwrap()).unwrap()).unwrap();
    })).await;
    let handle = client.identity.get_handles().await[0].clone();

    if register_only {
        info!("Registration complete. serial={}", config.get_serial_number());
        info!("Next: ./rustpush-test --test-lookup tel:+1...");
        info!("Or:  ./rustpush-test --export-bbox --output caches.json");
        drop(client);
        drop(connection);
        return;
    }

    if test_lookup {
        test_ids_lookup(&client, &handle).await;
        drop(client);
        drop(connection);
        return;
    }
    client.identity.ensure_private_self(&mut *client.identity.cache.lock().await, &handle, true).await.unwrap();

    // client.identity.refresh_now().await.unwrap();
    // println!("handle {}", handle);


    


    let id_path = PathBuf::from_str("cloudkit.plist").unwrap();
    let state: CloudKitState = plist::from_file(&id_path).unwrap();

    let token_provider = TokenProvider::new(account.clone(), config.clone());

    let cloudkit = Arc::new(CloudKitClient {
        state: DebugRwLock::new(state),
        anisette: anisette_client.clone(),
        config: config.clone(),
        token_provider: token_provider.clone(),
    });



    let id_path = PathBuf::from_str("profiles.plist").unwrap();
    let mut state: Option<ShareProfileMessage> = plist::from_file(&id_path).unwrap_or_default();
    let name_photo_client = ProfilesClient::new(cloudkit.clone());

    let listener = IdmsAuthListener::new(connection.clone()).await;

    // error!("2fa code: {}", anisette_client.lock().await.provider.get_2fa_code().await.unwrap());
    // plist::to_file_xml(&id_path, &state).unwrap();

    // let state: StatusKitState = plist::from_file("statuskit.plist").unwrap_or_default();
    // let statuskit_client = StatusKitClient::new(state, Box::new(|state| {
    //     plist::to_file_xml("statuskit.plist", state).unwrap();
    // }), , connection.clone(), config.clone(), client.identity.clone()).await;

    // statuskit_client.invite_to_channel("mailto:sandboxalt@gmail.com", &["mailto:jerrylandgreen@copper.jjtech.dev".to_string()]).await.unwrap();
    // statuskit_client.share_status(&StatusKitStatus::new_active()).await.unwrap();


    // let (token, _) = statuskit_client.request_handles(&["mailto:jerrylandgreen@copper.jjtech.dev".to_string(), "mailto:cooper@copper.jjtech.dev".to_string()]).await;

    // let session: CloudKitSession = CloudKitSession::new();
    // let (record, data) = name_photo_client.container.get_record::<_, TestRecord>(&session, &cloudkit, rustpush::cloudkit_proto::AssetsToDownload {
    //     all_assets: Some(true),
    //     asset_fields: None,
    // }, "+1ZvgjukQfNbTOQ4KJfjvA==-wp").await.unwrap();

            // let record = name_photo_client.get_record(&ShareProfileMessage {
            //     cloud_kit_decryption_record_key: vec![252, 89, 106, 62, 98, 168, 206, 27, 85, 204, 233, 177, 226, 226, 250, 105],
            //     cloud_kit_record_key: "+1ZvgjukQfNbTOQ4KJfjvA==".to_string(),
            //     poster: Some(SharedPoster {
            //         low_res_wallpaper_tag: vec![129, 56, 178, 150, 254, 45, 242, 22, 100, 117, 75, 159, 41, 71, 124, 179, 223, 216, 33, 32, 243, 16, 49, 208, 246, 222, 124, 232, 133, 190, 163, 168],
            //         wallpaper_tag: vec![224, 248, 168, 14, 40, 131, 159, 194, 205, 43, 88, 103, 235, 249, 191, 107, 30, 51, 116, 242, 199, 186, 3, 155, 150, 128, 156, 108, 30, 80, 86, 110],
            //         message_tag: vec![105, 108, 56, 149, 123, 86, 208, 11, 168, 187, 193, 190, 222, 121, 120, 69, 136, 245, 181, 223, 149, 195, 17, 38, 226, 187, 62, 200, 138, 143, 57, 239],
            //     }),
            // }).await.unwrap();

    // name_photo_client.set_record(record, &mut state).await.unwrap();

    // name_photo_client.set_record(IMessageNicknameRecord {
    //     name: IMessageNameRecord {
    //         name: "Testing Now".to_string(),
    //         first: "Testing".to_string(),
    //         last: "Now".to_string(),
    //     },
    //     image: fs::read("upload.png").await.unwrap()
    // }, &mut state).await.unwrap();

    // println!("name {:?}", record.n);

    let id_path = PathBuf::from_str("sharedstreams.plist").unwrap();
    let state: SharedStreamsState = plist::from_file(&id_path).unwrap();

    // let shared_streams = SharedStreamClient::new(state, Box::new(move |update| {
    //     plist::to_file_xml(&id_path, update).unwrap();
    // }), accou, connection.clone(), anisette_client.clone(), config.clone()).await;
    // shared_streams.get_changes().await.unwrap();
    // let album = shared_streams.state.read().await.albums[0].albumguid.clone();
    // shared_streams.get_album_summary(&album).await.unwrap();

    // let state: FTState = plist::from_file(&PathBuf::from_str("facetime.plist").unwrap()).unwrap_or_default();
    // let facetime = FTClient::new(state, Box::new(|state| {
    //     plist::to_file_xml(&PathBuf::from_str("facetime.plist").unwrap(), state).expect("Failed to serialize plist!");
    // }), connection.clone(), client.identity.clone(), config.clone()).await;

    let id_path = PathBuf::from_str("trustedpeers.plist").unwrap();
    let state: KeychainClientState = plist::from_file(&id_path).unwrap();

    let keychain = Arc::new(KeychainClient {
        anisette: anisette_client.clone(),
        token_provider: token_provider.clone(),
        state: DebugRwLock::new(state),
        config: config.clone(),
        update_state: Box::new(move |update| {
            plist::to_file_xml(&id_path, update).unwrap();
        }),
        container: tokio::sync::Mutex::new(None),
        security_container: tokio::sync::Mutex::new(None),
        client: cloudkit.clone(),
    });

    let id_path = PathBuf::from_str("findmy.plist").unwrap();
    let state = std::fs::read(&id_path).unwrap();
    let findmy_client = FindMyClient::new(connection.clone(), cloudkit.clone(), keychain.clone(), config.clone(), 
        FindMyStateManager::new(&state, Box::new(move |state| {
            std::fs::write(&id_path, state).unwrap()
        })), 
    token_provider.clone(), anisette_client.clone(), client.identity.clone()).await.unwrap();

    let state: PasswordState = plist::from_file("passwords.plist").unwrap_or_default();
    // let passwords = PasswordManager::new(
    //     keychain.clone(), cloudkit.clone(), client.identity.clone(), connection.clone(), state, Box::new(move |state| {
    //         plist::to_file_xml("passwords.plist", state).unwrap();
    //     })).await;


    if let Some(mut s) = session {
        let mut subscription = connection.messages_cont.subscribe();
        s.setup_trusted_peers(keychain.clone(), b"antifa").await.unwrap();
        let listener = IdmsAuthListener::new(connection.clone()).await;
        let anisette_client = anisette_client.clone();
        tokio::task::spawn(async move {
            loop {
                let msg = subscription.recv().await.unwrap();
                
                if let Some(test) = listener.handle(msg.clone()).unwrap() {
                    info!("watching {test:?}");
                    match test {
                        IdmsMessage::TeardownSignIn(_) => info!("Teardown sign in"),
                        IdmsMessage::RequestedSignIn(_) => info!("requested sign in code {}", anisette_client.lock().await.provider.get_2fa_code().await.unwrap()),
                        IdmsMessage::CircleRequest(c, _) => {
                            s.handle_circle_request(&c).await.unwrap();
                        }
                    }
                }
            }
        });
    } else {
        pub fn base64_encode(data: &[u8]) -> String {
            general_purpose::STANDARD.encode(data)
        }

        pub fn base64_decode(data: &str) -> Vec<u8> {
            general_purpose::STANDARD.decode(data).unwrap()
        }
        // keychain.sync_changes().await.unwrap();
        // info!("Fetching tlk");

        // let container = keychain.get_security_container().await.unwrap();

        let cloud_messages = CloudMessagesClient::new(cloudkit.clone(), keychain.clone());
        // cloud_messages.sync_attachments(None).await.unwrap();
        
        // cloud_messages.fix().await.unwrap();
        // // cloud_messages.get_msg().await.unwrap();
        // let storage_info = token_provider.get_storage_info().await.unwrap();
        // println!("{:#?}", storage_info);

        // keychain.reset_clique(b"antifa").await.unwrap();

        // findmy_client.sync_item_positions().await.unwrap();
        // findmy_client.update_beacon_name(&BeaconNamingRecord {
        //     emoji: "????".to_string(),
        //     name: "test4???s hielalf".to_string(),
        //     associated_beacon: "2793F9C5-5660-4F56-96D3-26A91859F982".to_string(),
        //     role_id: 10,
        // }).await.unwrap();

        // let bottles = keychain.get_viable_bottles().await.unwrap().remove(0);
        // println!("import password for {}", bottles.1.serial);
        // let mut input = String::new();
        // std::io::stdin().read_line(&mut input).unwrap();
        // let item = input.trim().to_string();
        // keychain.join_clique_from_escrow(&bottles.0, item.as_bytes(), b"antifa").await.unwrap();

        // keychain.sync_keychain(&KEYCHAIN_ZONES).await.unwrap();

        let container = keychain.get_security_container().await.unwrap();
        // let container = passwords.get_container().await.unwrap();

        // let zone = container.private_zone("group-93757E7E-7715-4557-8709-A7CEEC968BFE".to_string());
        // let pcs_config = container.get_zone_encryption_config(&zone, &keychain, &SHARED_PASSWORDS_SERVICE).await.unwrap();
        // let mut zone = container.get_zone_share(&zone, &pcs_config).await.unwrap();


        // let zone = container.shared_zone("group-DE1587A8-88FB-4363-B29F-6A2D5A6518F8".to_string(), "_a049d4a4a0f3dafd37d508781b723960".to_string());
        // let pcs_config = container.get_zone_encryption_config(&zone, &keychain, &SHARED_PASSWORDS_SERVICE).await.unwrap();
        // let mut zone = container.get_zone_share(&zone, &pcs_config).await.unwrap();


        // container.create_sync_subscription().await.unwrap();
        keychain.create_subscriptions().await.unwrap();
        // container.register_token(&connection).await.unwrap();


        // passwords.sync_passwords().await.unwrap();
        // tokio::time::sleep(Duration::from_secs(10)).await;
        // passwords.sync_passwords().await.unwrap();

        // container.update_zone_share(pcs_config, &keychain, &SHARED_PASSWORDS_SERVICE, &mut zone).await.unwrap();


        // passwords.test().await.unwrap();


        // PCSPrivateKey::get_service_key(&keychain, &SHARED_PASSWORDS_SERVICE, config.as_ref()).await.unwrap();

        // let state = keychain.state.read().await;
        // let items = state.items["Manatee"].current_keys.get("com.apple.ProtectedCloudStorage-com.apple.security.keychain.shared").unwrap().clone();
        // drop(state);
        // keychain.delete_keychain(&items, "Manatee").await.unwrap();
        
        // passwords.test().await.unwrap();

        // let id = passwords.create_group("three, two, e").await.unwrap();
        // passwords.invite_user("8AC8FD27-B9AE-4EFE-A605-72E55A635023", "mailto:sandboxalt@gmail.com").await.unwrap();
        // passwords.remove_user("8AC8FD27-B9AE-4EFE-A605-72E55A635023", "mailto:sandboxalt@gmail.com").await.unwrap();



        // panic!("{:?}", zone);


        // findmy_client.accept_item_share("CA065844-8DA5-4F99-AE74-858DEABA34DE").await.unwrap();
        // findmy_client.sync_items(true).await.unwrap();
        // findmy_client.delete_shared_item("404B1239-49C2-4670-B9AA-E51313015540").await.unwrap();


        // findmy_client.sync_item_positions().await.unwrap();

        // let state = findmy_client.state.state.lock().await;
        // let i = state.share_state.secrets.values().find_map(|i| i.circle_shared_secret()).unwrap();
        // let plaint = i.decrypt(&base64_decode("YnBsaXN0MDCjAQIDTHlKsVsp07xJc17kmU8QEMsGEV485/wUHWXNp9+5rLJPEK3d3u3/TgCaEVyHoEaF/R7dYoTkXBnGA6//m5Z9FT0kkUcqsikEbWabeJqDIVjwyHTIQX5BqApt0J36Gsf2N/pU+zEXIrkkNcRRsENNSABVpd1iBP474tG24rhPlksfHgDIrvUIiHG4xwbnNSDWaHMuFk6pqDwqsuHolXYJAOko147a6oIEnLi9OifR6RNRyxL4+REDSmNP5/Dd4cd6AzcX+JcSDBm4yO79pCzy3wgMGSwAAAAAAAABAQAAAAAAAAAEAAAAAAAAAAAAAAAAAAAA3A==")).unwrap();

        // println!("here {}", base64_encode(&plaint));

        // println!("{}", base64_encode(&decrypt_shared_key(&s, 114)));
        

        // keychain.change_escrow_password(b"escraw!").await.unwrap();
        // cloud_messages.insert_message().await.unwrap();

        // let messages_container = cloud_messages.get_container().await.unwrap();

        // let chat_zone = messages_container.private_zone("chatManateeZone".to_string());

        // messages_container.perform(&CloudKitSession::new(), 
        //     ZoneDeleteOperation::new(messages_container.private_zone("chatManateeZone".to_string()))).await.unwrap();

        // let key = messages_container.get_zone_encryption_config(&chat_zone, &keychain).await.unwrap();

        // panic!();

        // container.perform(&CloudKitSession::new(), 
        //     ZoneDeleteOperation::new(container.private_zone("Engram".to_string()))).await.unwrap();

        // container.perform(&CloudKitSession::new(), 
        //     ZoneSaveOperation::new(container.private_zone("Engram".to_string()), None).unwrap()).await.unwrap();

        
        // messages_container.perform(&CloudKitSession::new(), 
        //     ZoneDeleteOperation::new(messages_container.private_zone("messageManateeZone".to_string()))).await.unwrap();

        // messages_container.perform(&CloudKitSession::new(), 
        //     ZoneDeleteOperation::new(messages_container.private_zone("attachmentManateeZone".to_string()))).await.unwrap();

        // cloud_messages.insert_message().await.unwrap();

        
        // container.perform(&CloudKitSession::new(), 
        //     ZoneSaveOperation::new(container.private_zone("chatManateeZone".to_string()), Some(&key.key())).unwrap()).await.unwrap();

        // let key = keychain.state.read().await;
        // let (item, record) = &key.items["50BE8D1A-ED50-7D7F-3BE5-D51A26953A90"];
        // let decoded = item.decrypt("50BE8D1A-ED50-7D7F-3BE5-D51A26953A90", &record.0, &key);
        
        // panic!("here {}", encode_hex(&decoded));


        // let key = keychain.state.read().await;
        // let item = key.get_key_id("A6F86BA3-9A98-4F12-B34C-309682A5B05C").unwrap();
        // let result = item.decrypt(&base64_decode("4LAUq+5FDtCUx0JD451YLW9AgYOyE2vtnvqUmjF0oZ7qZf7pGjqaqYiUCC9MeJn3IrsgGMNZh2Q5BwIObynz80Q+k/uke99KPxn0kCkY8uE="));

        // let payload = decode_hex("f6e83f171e336dbbce643a843b339797716f0a8300c08c3828cb9abe2c47e7fb9f57e4950c7b764678ce9db0863585648b8829007734acc3682dcdb217afb0e01dd0ae0bc7e195a71786c14190058aaf609ca656acb52896397a680af50ce856bb2e898dbb7ff8d5b7fdf91a0215d70f7a8d2313dcc506100f12f36666512d417059fe0dcdb46f56449f58b66c66124929e1fa74c2c4878bb2e5f422e09062bcd9ad9cde6e4e4209033888f946793e0f885e5d5c685466b3e6f6201bf15ebb8b70c20a3e14498ab29b54356e6bbbcaa9b7c48fe116801fcee0376ee563065ba190674f340d60cce0328fe502ba2bffdbcf6eb8afa60190ef7b5d224b60ac4f850668a1094639113685edf53189588ff4e7d876651946bb19efee28f2893912dbc4c89c82862616d3e4bbaf36e780bc6f71a0cf230450134a4af9458906e8c08b968e4a1e2f4d62f96ab03a5ab75dd838efbb03d14a2361232cc7f7b3206782e2a4c084ff2a76bab0891062c855e7b6bb9336f35f17cdf53ea1ce8ab3ff00806ab8894c9848e79beea45baeb7233539b4aea4ea8a11bc3588a19779fa7778f0318acc067ca79e45dbafdeaaec080d04aaeb3c359ee5f764644adfbe2bd18a46d1ba9d7551c1482e305c39c1b176eeaa6e53d234169865e475cc4a5720cc017f4b0a4e1b4d22efa7cfa51a91a20d585e782a25a98da4318a9f0f560e190a8eb5a081187e78b27af2d5cb1f9ccbe46420e4e380df424fab609248ae58e58588c53ed75d992ca54f98807073fadeb253021b45335bf79e719fd67b9775258703c46e570c4ce85e7d3f2fa06cba6e7670c1c5de75f943827866fdd7849274828708476fe9b8ba50e6149734f284ea7fe7e7d4e1eb6b3f56da2b93288b2e8874186f71c333604cc916aecadb2fd25dc5a1fc0cbfacdb2d310d18d6c8b8a0ba0b14017751e9cb5e3f48689c13e09366ca7fcf2d39c468c30dee0cf9022d92614c2917185f752e1565230268fa5e04d454b73702e5857ebf14f1060c3fc6322c3abbaf5ea9ed2b5738da5fdeb2fa5054ae0aa28aef1968269569212f5d370ddf5d4ccfa84487f0b5db29adb3bcb4d218237f9136c488a1b08e1c4e938c4a437f84500d8bea65226a750fd62da5a2de0ceb1a79cc1f77cc98bfc06abff241711fdbd66aa4").unwrap();
       
        // use aes_siv::KeyInit;
        // use aes_siv::aead::Aead;
        // let cipher = Aes256SivAead::new_from_slice(&result).unwrap();
        // let nonce = Nonce::from_slice(&payload[..16]); // 96-bits; unique per message
        // let plaintext = cipher.decrypt(nonce, &payload[16..]).unwrap();
        // panic!("here {}", encode_hex(&plaintext));
    }


    // keychain.delete("com.apple.icdp.record.SHA256:s6BbbQzQwtlO+zxiVS/OXOeNXJkGBnS4dtiCeguTbYI=").await.unwrap();
    // keychain.enroll().await.unwrap();
    // keychain.recover_bottle("com.apple.icdp.record.lJjYEopJu5QWIF+W7wjsavhZ16", "000000".as_bytes()).await.unwrap();

    // keychain.sync_trust().await.unwrap();
    // keychain.reset_trust().await.unwrap();

    // panic!("result {}", general_purpose::STANDARD.encode(&dec));
    


    // let mut ft_lock = facetime.state.write().await;
    // facetime.remove_members(&mut ft_lock.sessions.values_mut().next().unwrap(), vec![
    //     FTMember {
    //         nickname: None,
    //         handle: "tel:+18183857117".to_string(),
    //     }
    // ]).await.expect("Could not remove");
    // drop(ft_lock);

    // let link = facetime.generate_link(&handle).await.expect("Failed to create facetime link!");
    // info!("Facetime link {}", link);



    // facetime.create_session(Uuid::new_v4().to_string().to_uppercase(), handle.clone(), &["".to_string()]).await.expect("Failed to create session!");
    // info!("Rung!");


    // let manager = SyncController::new(shared_streams, PathBuf::from_str("syncstate.plist").unwrap(), FFMpegFilePackager::default(), Duration::from_secs(60 * 30)).await;


    
    // plist::to_file_xml("syncstate.plist", &syncstate).unwrap();



    // pub fn encode_hex(bytes: &[u8]) -> String {
    //     let mut s = String::with_capacity(bytes.len() * 2);
    //     for &b in bytes {
    //         write!(&mut s, "{:02x}", b).unwrap();
    //     }
    //     s
    // }


    // let batch_date_created = SystemTime::now();
    // let batch_guid = Uuid::new_v4().to_string().to_uppercase();

    // let mut file = File::open("IMG_0153.HEIC").unwrap();
    // let mut file_container = FileContainer::new(None, Some(&mut file));
    // let derivative_pre = prepare_put(&mut file_container, true, 0x01).await.unwrap();

    // let mut file = File::open("thumbnail_B0E9F348-BE67-4AE6-B7B6-18220D6A7AE1.HEIC").unwrap();
    // let mut file_container = FileContainer::new(None, Some(&mut file));
    // let thumb_pre = prepare_put(&mut file_container, true, 0x01).await.unwrap();

    // let asset = AssetDetails {
    //     filename: format!("{}.HEIC", Uuid::new_v4().to_string().to_uppercase()),
    //     assetguid: Uuid::new_v4().to_string().to_uppercase(),
    //     createdbyme: "1".to_string(),
    //     candelete: "1".to_string(),
    //     collectionmetadata: CollectionMetadata {
    //         batch_date_created: round_seconds(batch_date_created).into(),
    //         batch_guid,
    //         date_created: round_seconds(fs::metadata("149E5C12-E3BD-4A82-B8B8-5F2E44DA0260.HEIC").await.unwrap().created().unwrap()).into(),
    //         playback_variation: 0,
    //     },
    //     files: vec![AssetFile {
    //         size: derivative_pre.total_len.to_string(),
    //         checksum: encode_hex(&derivative_pre.total_sig),
    //         width: "1536".to_string(),
    //         height: "2048".to_string(),
    //         file_type: "public.jpeg".to_string(),
    //         url: Default::default(),
    //         token: Default::default(),
    //         metadata: AssetMetadata {
    //             asset_type: "derivative".to_string(),
    //             asset_type_flags: 2,
    //         }
    //     },AssetFile {
    //         size: thumb_pre.total_len.to_string(),
    //         checksum: encode_hex(&thumb_pre.total_sig),
    //         width: "257".to_string(),
    //         height: "342".to_string(),
    //         file_type: "public.jpeg".to_string(),
    //         url: Default::default(),
    //         token: Default::default(),
    //         metadata: AssetMetadata {
    //             asset_type: "thumbnail".to_string(),
    //             asset_type_flags: 1,
    //         }
    //     }]
    // };

    // let mut der = File::open("IMG_0153.HEIC").unwrap();
    // let mut thum = File::open("thumbnail_B0E9F348-BE67-4AE6-B7B6-18220D6A7AE1.HEIC").unwrap();
    // shared_streams.create_asset(&shared_streams.albums[0].albumguid.clone(), vec![asset], vec![(derivative_pre, &mut der), (thumb_pre, &mut thum)], &mut |_a, _b| {}).await.unwrap();


    // let batch_date_created = SystemTime::now();
    // let batch_guid = Uuid::new_v4().to_string().to_uppercase();

    // let mut der = File::open("JPG_Test.jpg").unwrap();
    // let (asset, prepared) = AssetDetails::from_file(PathBuf::from_str("JPG_Test.jpg").unwrap(), batch_date_created, batch_guid).await.unwrap();
    // shared_streams.create_asset(&shared_streams.albums[0].albumguid.clone(), vec![asset], vec![(prepared, &mut der)], &mut |_a, _b| {}).await;


    // shared_streams.get_album_summary(&shared_streams.albums[0].albumguid.clone()).await.unwrap();
    // let assets = shared_streams.get_assets(&shared_streams.albums[0].albumguid.clone(), &shared_streams.albums[0].assets.clone()).await.unwrap();
    // let mut files: Vec<_> = assets.iter().flat_map(|a| {
    //     a.files.iter().map(|file| (file, File::create(format!("mine{}_{}", file.metadata.asset_type, &a.filename)).unwrap()))
    // }).collect();
    // let mut copy: Vec<_> = files.iter_mut().map::<(&AssetFile, &mut (dyn Write + Send + Sync)), _>(|a| {
    //     (a.0, &mut a.1)
    // }).collect();
    // shared_streams.get_file(&mut copy, &mut |_a, _b| {}).await.unwrap();


    // println!("here {:?}", shared_streams.albums);

    // client.identity.refresh_now().await.unwrap();


    //sleep(Duration::from_millis(10000)).await;

    let mut filter_target = String::new();

    let mut read_task = tokio::spawn(read_input());

    print!(">> ");
    std::io::stdout().flush().unwrap();

    let mut received_msgs = vec![];
    let mut last_ft_guid = "AE271F00-2F67-42C4-8EF2-74600055A2B7".to_string();
    
    let mut circle_session: Option<CircleServerSession<DefaultAnisetteProvider>> = None;

    let push_token = connection.get_token().await;
    
    loop {
        tokio::select! {
            msg = subscription.recv() => {
                let msg = msg.unwrap();
                // if let Err(e) = passwords.handle(msg.clone()).await {
                //     info!("err {e}");
                // }
                // if let Err(e) = findmy_client.handle(msg.clone()).await {
                //     info!("err {e}");
                // }
                // let _ = manager.handle(msg.clone()).await;
                
                // if let Some(test) = listener.handle(msg.clone()).unwrap() {
                //     info!("here {test:?}");
                //     match test {
                //         IdmsMessage::TeardownSignIn(_) => info!("Teardown sign in"),
                //         IdmsMessage::RequestedSignIn(_) => info!("requested sign in code {}", anisette_client.lock().await.provider.get_2fa_code().await.unwrap()),
                //         IdmsMessage::CircleRequest(c, _) => {
                //             if circle_session.is_none() {
                //                 let mut rng = rand::thread_rng();
                //                 let otp: u32 = rng.gen_range(0..1_000_000);
                //                 info!("requested sign in code {}", otp);
                //                 circle_session = Some(CircleServerSession::new(21635836012, otp, account.clone(), push_token, Some(keychain.clone())))
                //             }

                //             circle_session.as_mut().unwrap().handle_circle_request(&c).await.unwrap();
                //         }
                //     }
                // }

                // keychain.handle(msg.clone()).await.unwrap();

                // if let Err(e) = statuskit_client.handle(msg.clone()).await {
                //     error!("Statuskit error {e}");
                //     continue;
                // }
                // match facetime.handle(msg.clone()).await {
                //     Err(e) => {
                //         error!("Failed to receive {}", e);
                //         continue;
                //     },
                //     Ok(None) => {},
                //     Ok(Some(a)) => {
                //         info!("Got ftmessage {a:?}");
                //         match a {
                //             FTMessage::LetMeInRequest(request) => {
                //                 if request.delegation_uuid.is_none() {
                //                     if let Err(e) = facetime.respond_letmein(request, Some(&last_ft_guid)).await {
                //                         warn!("Failed {e}");
                //                     }
                //                     // facetime.respond_letmein(request, None).await.expect("Request failed");
                //                 }
                //             },
                //             FTMessage::JoinEvent { guid, ring, .. } => {
                //                 // if ring {
                //                 //     warn!("Preparing to decline!");
                //                 //     tokio::time::sleep(Duration::from_secs(10)).await;
                //                 //     let mut lock = facetime.state.write().await;
                //                 //     let state = lock.sessions.values_mut().find(|a| a.group_id == guid).expect("state");
                //                 //     facetime.ensure_allocations(state, &[]).await.expect("state");
                //                 //     facetime.decline_invite(state).await.expect("failed to unprop?");
                //                 // }
                //                 last_ft_guid = guid;
                //             },
                //             _ => {}
                //         }
                //     }
                // }
                let msg = client.handle(msg).await;
                if msg.is_err() {
                    error!("Failed to receive {}", msg.err().unwrap());
                    continue;
                }
                if let Ok(Some(msg)) = msg {
                    if msg.has_payload() && !received_msgs.contains(&msg.id) {
                        received_msgs.push(msg.id.clone());
                        // if let Message::ShareProfile(message) = &msg.message {
                        //     if let Err(e) = name_photo_client.get_record(&message).await {
                        //         error!("{e}");
                        //     }
                        // }
                        // if let Message::UpdateProfile(UpdateProfileMessage { profile: Some(profile), .. }) = &msg.message {
                        //     if let Ok(record) = name_photo_client.get_record(&profile).await {
                        //         // handle_record(record, &client, &name_photo_client, &profile).await;
                        //     }
                        // }
                        // if let Message::UpdateProfile(UpdateProfileMessage { profile: Some(profile), .. }) = &msg.message {
                        //     if let Ok(record) = name_photo_client.get_record(&profile).await {
                        //         // handle_record(record, &client, &name_photo_client, &profile).await;
                        //     }
                        // }
                        // if let Message::SetTranscriptBackground(msg) = &msg.message {
                        //     if let Some(mmcs) = msg.to_mmcs() {
                        //         let mut output = vec![];
                        //         let file = Cursor::new(&mut output);
                        //         mmcs.get_attachment(&*connection, file, |a, b| { }).await.unwrap();
                        //         SimplifiedTranscriptPoster::parse_payload(&output).unwrap();
                        //     }
                        // }
                        println!("{}", msg);
                        print!(">> ");
                        std::io::stdout().flush().unwrap();
                        if let Some(context) = msg.certified_context {
                            println!("sending delivered {}", msg.send_delivered);
                            client.identity.certify_delivery("com.apple.madrid", &context, false).await.unwrap();
                        }
                    }
                }
            // },
            // input = &mut read_task => {
            //     let Ok(input) = input else {
            //         read_task = tokio::spawn(read_input());
            //         continue;
            //     };
            //     if input.trim() == "" {
            //         print!(">> ");
            //         std::io::stdout().flush().unwrap();
            //         read_task = tokio::spawn(read_input());
            //         continue;
            //     }
            //     if input.starts_with("filter ") {
            //         filter_target = input.strip_prefix("filter ").unwrap().to_string().trim().to_string();
            //         println!("Filtering to {}", filter_target);
            //     } else if input.trim() == "sms" {
            //         let mut msg = MessageInst::new(ConversationData {
            //             participants: vec![],
            //             cv_name: None,
            //             sender_guid: Some(Uuid::new_v4().to_string()),
            //             after_guid: None,
            //         }, &handle, Message::EnableSmsActivation(true));
            //         client.send(&mut msg).await.unwrap();
            //         println!("sms activated");
            //     } else {
            //         if filter_target == "" {
            //             println!("Usage: filter [target]");
            //         } else {
            //             let mut msg = NormalMessage::new(input.trim().to_string(), MessageType::IMessage);
            //             // msg.scheduled_ms = Some((SystemTime::now() + Duration::from_secs(60)).duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis() as u64);
            //             let mut msg = MessageInst::new(ConversationData {
            //                 participants: vec![filter_target.clone()],
            //                 cv_name: None,
            //                 sender_guid: Some(Uuid::new_v4().to_string()),
            //                 after_guid: None,
            //             }, &handle, Message::Message(msg));

            //             // msg.scheduled_ms = Some((SystemTime::now() + Duration::from_secs(60)).duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis() as u64);

            //             if let Err(err) = client.send(&mut msg).await {
            //                 error!("Error sending message {err}");
            //             }

            //             // tokio::time::sleep(Duration::from_secs(10)).await;

            //             // msg.message = Message::Unschedule;
            //             // if let Err(err) = client.send(&mut msg).await {
            //             //     error!("Error sending message {err}");
            //             // }
            //         }
            //     }
                print!(">> ");
                std::io::stdout().flush().unwrap();
                read_task = tokio::spawn(read_input());
            },
        }
    }
}


#[test]
fn test() {
    let client_nonce: [u8; 32] = rand::random();
    panic!("e {}", base64_encode(&client_nonce))
}
