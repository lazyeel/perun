// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! The App Store operations: login, search, lookup, purchase, download,
//! purchase history, version listing. Port of the reference tool's wire
//! behavior (majd/ipatool v2.4.0), with the SAP action signature produced
//! natively by the Perun runtime instead of an emulator.

use super::account::Account;
use super::bag::SAPConfig;
use super::http::{self, Request};
use super::json::{self, Json};
use super::plist::{self, Plist};
use super::signer::Signer;

pub const ITUNES_SEARCH: &str = "https://itunes.apple.com/search";
pub const ITUNES_LOOKUP: &str = "https://itunes.apple.com/lookup";
pub const BUY_DOMAIN: &str = "buy.itunes.apple.com";
pub const PATH_PURCHASE: &str = "/WebObjects/MZFinance.woa/wa/buyProduct";
pub const PATH_DOWNLOAD: &str = "/WebObjects/MZFinance.woa/wa/volumeStoreDownloadProduct";
pub const PURCHASE_DAAP_BASE: &str =
    "https://pd.itunes.apple.com/WebObjects/MZPurchaseDaap.woa/purchase";

// Failure types the store reports in-band.
pub const FAILURE_INVALID_CREDENTIALS: &str = "-5000";
pub const FAILURE_INVALID_AUTH_CODE: &str = "5005";
pub const FAILURE_PASSWORD_TOKEN_EXPIRED: &str = "2034";
pub const FAILURE_SIGN_IN_REQUIRED: &str = "2042";
pub const FAILURE_LICENSE_NOT_FOUND: &str = "9610";
pub const FAILURE_TEMPORARILY_UNAVAILABLE: &str = "2059";
pub const FAILURE_LICENSE_ALREADY_EXISTS: &str = "5002";
pub const FAILURE_DEVICE_VERIFICATION_FAILED: &str = "1008";
pub const MSG_BAD_LOGIN: &str = "MZFinance.BadLogin.Configurator_message";
pub const MSG_ACCOUNT_DISABLED: &str = "Your account is disabled.";
pub const MSG_SUBSCRIPTION_REQUIRED: &str = "Subscription Required";
pub const MSG_PASSWORD_CHANGED: &str = "Your password has changed.";
pub const PRICING_APPSTORE: &str = "STDQ";
pub const PRICING_ARCADE: &str = "GAME";

/// Error taxonomy shared with the CLI layer.
#[derive(Debug)]
pub enum StoreError {
    /// Apple rejected credentials and no 2FA code was supplied.
    AuthCodeRequired,
    /// The supplied 2FA code was rejected or has expired (failureType 5005
    /// or its equivalent shapes; upstream's mapping).
    InvalidAuthCode,
    PasswordTokenExpired,
    LicenseRequired,
    LicenseAlreadyExists,
    SubscriptionRequired,
    TemporarilyUnavailable,
    AccountDisabled,
    AppNotFound,
    PaidApp,
    Other(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::AuthCodeRequired => write!(f, "auth code is required"),
            StoreError::InvalidAuthCode => write!(
                f,
                "2FA code rejected or expired — request a fresh code and retry"
            ),
            StoreError::PasswordTokenExpired => write!(f, "password token is expired"),
            StoreError::LicenseRequired => write!(f, "license is required"),
            StoreError::LicenseAlreadyExists => write!(f, "license already exists"),
            StoreError::SubscriptionRequired => write!(f, "subscription required"),
            StoreError::TemporarilyUnavailable => write!(f, "item is temporarily unavailable"),
            StoreError::AccountDisabled => write!(f, "account is disabled"),
            StoreError::AppNotFound => write!(f, "app not found"),
            StoreError::PaidApp => write!(f, "purchasing paid apps is not supported"),
            StoreError::Other(msg) => write!(f, "{msg}"),
        }
    }
}

pub type Result<T> = std::result::Result<T, StoreError>;

/// One app from the iTunes Search API.
#[derive(Clone, Debug, Default)]
pub struct App {
    pub id: i64,
    pub bundle_id: String,
    pub name: String,
    pub version: String,
    pub price: f64,
    pub purchase_date: Option<String>,
}

impl App {
    fn from_search_json(item: &Json) -> App {
        let get = |key: &str| item.get(key).and_then(|v| v.as_str()).unwrap_or("");
        App {
            id: item.get("trackId").and_then(|v| v.as_i64()).unwrap_or(0),
            bundle_id: get("bundleId").to_string(),
            name: get("trackName").to_string(),
            version: get("version").to_string(),
            price: item.get("price").and_then(|v| v.as_f64()).unwrap_or(0.0),
            purchase_date: None,
        }
    }
}

/// guid: upper-case hex MAC without separators.
pub fn guid_from_mac(mac: &[u8; 6]) -> String {
    mac.iter().map(|b| format!("{b:02X}")).collect()
}

// ── login ─────────────────────────────────────────────────────────────────

/// MZFinance authenticate. Returns the account with session tokens.
/// The `auth_code` (from push, SMS fallback, or hardware key) is appended
/// to the password on the retry round — Apple's only 2FA channel here.
pub fn login(
    email: &str,
    password: &str,
    auth_code: &str,
    mac: [u8; 6],
    signer: &mut Signer,
    config: &SAPConfig,
) -> Result<Account> {
    let guid = guid_from_mac(&mac);
    let mut attempt = 1;
    let mut redirect: Option<String> = None;
    let mut effective_password = password.to_string();
    if !auth_code.is_empty() {
        effective_password = format!("{}{}", password, auth_code.replace(' ', ""));
    }

    'attempts: loop {
        if attempt > 4 {
            return Err(StoreError::Other("too many attempts".into()));
        }

        let mut payload = Plist::dict();
        payload.set("appleId", Plist::string(email));
        payload.set("attempt", Plist::string(attempt.to_string()));
        payload.set("guid", Plist::string(&guid));
        payload.set("password", Plist::string(&effective_password));
        payload.set("rmp", Plist::string("0"));
        payload.set("why", Plist::string("signIn"));
        let body = plist::to_xml(&payload).into_bytes();

        let (name, value) = signer
            .sign_header(&body)
            .map_err(|e| StoreError::Other(format!("sign login body: {e}")))?;

        let url = redirect
            .clone()
            .unwrap_or_else(|| config.auth_endpoint.clone());
        // Edge-drops (Kosthi/ipatool-rs#19): Apple's edge sometimes sheds
        // requests before they reach MZFinance — a 3xx with no Location, a
        // 204/404/5xx with an empty or HTML body and no backend headers.
        // The identical signed bytes are resent up to 3 times, 250 ms
        // apart; 403 (the real "no signature" verdict) and 429 (rate
        // limit) are never resent.
        let mut res = http::send(
            Request::new("POST", &url)
                .header(&name, &value)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .form_body(body.clone())
                .stop_on_redirect_marker(),
        )
        .map_err(|e| StoreError::Other(format!("login request: {e}")))?;
        for resend in 1..=2 {
            let has_store_verdict = res.status == 403
                || res.status == 429
                || res.body.starts_with(b"<?xml")
                || res.body.starts_with(b"<plist")
                || res.body.starts_with(b"<Document")
                || res.body.starts_with(b"<!DOCTYPE");
            let dropped = matches!(res.status, 204 | 404)
                || res.status >= 500
                || ((301..=399).contains(&res.status)
                    && res.status != 304
                    && res.header("location").is_none());
            if has_store_verdict || !dropped {
                break;
            }
            eprintln!(
                "[store] login send {} dropped by the edge (HTTP {}), resending",
                resend, res.status
            );
            std::thread::sleep(std::time::Duration::from_millis(250));
            res = http::send(
                Request::new("POST", &url)
                    .header(&name, &value)
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .form_body(body.clone())
                    .stop_on_redirect_marker(),
            )
            .map_err(|e| StoreError::Other(format!("login request: {e}")))?;
        }

        // Pod redirect: re-POST the ORIGINAL body (attempt value included).
        if (301..=399).contains(&res.status)
            && res.status != 304
            && let Some(location) = res.header("location")
        {
            let location = location.to_string();
            if location.contains("itms-apps://") || !location.starts_with("https://") {
                return Err(StoreError::Other(format!(
                    "unsupported redirect: {location}"
                )));
            }
            redirect = Some(location);
            // Same attempt number: the pod hop is part of one attempt.
            continue 'attempts;
        }

        if res.status == 204 || res.status == 404 || res.status >= 500 {
            // Retryable: Apple's LBs occasionally shed requests.
            attempt += 1;
            std::thread::sleep(std::time::Duration::from_millis(250 * attempt as u64));
            continue 'attempts;
        }

        let doc = match plist::parse_xml(&res.body) {
            Ok(doc) => doc,
            Err(e) => {
                return Err(StoreError::Other(format!(
                    "login response parse (HTTP {}): {}",
                    res.status, e
                )));
            }
        };

        let failure_type = doc
            .get("failureType")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let customer_message = doc
            .get("customerMessage")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        // -5000 on attempt 1 = Apple wants the 2FA-augmented password.
        if attempt == 1 && failure_type == FAILURE_INVALID_CREDENTIALS && auth_code.is_empty() {
            attempt += 1;
            continue 'attempts;
        }
        // Invalid or expired 2FA code — the three shapes Apple reports it
        // in (upstream's fix, mapped the same way):
        //   1. failureType 5005 outright,
        //   2. -5000 again AFTER a code was already appended,
        //   3. BadLogin message once a code is in play.
        if failure_type == FAILURE_INVALID_AUTH_CODE
            || (failure_type == FAILURE_INVALID_CREDENTIALS && !auth_code.is_empty())
            || (failure_type.is_empty()
                && !auth_code.is_empty()
                && customer_message == MSG_BAD_LOGIN)
        {
            return Err(StoreError::InvalidAuthCode);
        }
        if failure_type.is_empty() && auth_code.is_empty() && customer_message == MSG_BAD_LOGIN {
            return Err(StoreError::AuthCodeRequired);
        }
        if failure_type.is_empty() && customer_message == MSG_ACCOUNT_DISABLED {
            return Err(StoreError::AccountDisabled);
        }
        if !failure_type.is_empty() {
            return Err(StoreError::Other(if customer_message.is_empty() {
                format!("login failed: failureType {failure_type}")
            } else {
                customer_message
            }));
        }

        let password_token = doc
            .get("passwordToken")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let dsid = doc
            .get("dsPersonId")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let account_email = doc
            .get("accountInfo")
            .and_then(|v| v.get("appleId"))
            .and_then(|v| v.as_str())
            .unwrap_or(email)
            .to_string();
        let (first, last) = {
            let addr = doc
                .get("accountInfo")
                .and_then(|v| v.get("address"))
                .cloned()
                .unwrap_or_else(Plist::dict);
            (
                addr.get("firstName")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                addr.get("lastName")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
            )
        };
        let name = format!("{first} {last}").trim().to_string();

        if res.status != 200 || password_token.is_empty() || dsid.is_empty() {
            if std::env::var("PERUN_STORE_HTTP_DEBUG").is_ok() {
                eprintln!(
                    "[store:login] raw body ({} bytes): {}",
                    res.body.len(),
                    String::from_utf8_lossy(&res.body)
                );
                eprintln!("[store:login] headers: {:?}", res.headers);
            }
            if customer_message == MSG_BAD_LOGIN {
                return Err(StoreError::Other(
                    "invalid credentials (password or 2FA code)".into(),
                ));
            }
            let snippet = String::from_utf8_lossy(&res.body)
                .chars()
                .take(300)
                .collect::<String>();
            return Err(StoreError::Other(format!(
                "login failed (HTTP {}, failureType={failure_type:?}, message={customer_message:?}): {snippet}",
                res.status
            )));
        }

        let store_front = res
            .header("x-set-apple-store-front")
            .unwrap_or("")
            .to_string();
        let pod = res.header("pod").unwrap_or("").to_string();

        return Ok(Account {
            email: account_email,
            name,
            directory_services_id: dsid,
            password_token,
            store_front,
            pod,
            password: String::new(),
        });
    }
}

// ── search / lookup ───────────────────────────────────────────────────────

/// `entity` for the platform word ("" = mixed iphone/ipad).
pub fn search_entity(platform: &str) -> &'static str {
    match platform {
        "iphone" | "ios" => "software",
        "ipad" | "ipados" => "iPadSoftware",
        "appletv" | "tvos" => "software,tvSoftware",
        "visionos" => "xrosSoftware",
        "macos" => "macSoftware",
        _ => "software,iPadSoftware",
    }
}

pub fn lookup_entity(platform: &str) -> &'static str {
    match platform {
        "iphone" | "ios" => "software",
        "ipad" | "ipados" => "iPadSoftware",
        "appletv" | "tvos" => "tvSoftware",
        "visionos" => "xrosSoftware",
        "macos" => "macSoftware",
        _ => "software,iPadSoftware",
    }
}

pub fn country_code_from_storefront(storefront: &str) -> Result<&'static str> {
    let id = storefront.split('-').next().unwrap_or("");
    for (code, sf) in super::storefronts::STOREFRONTS {
        if *sf == id {
            return Ok(code);
        }
    }
    Err(StoreError::Other(format!(
        "country code mapping for storefront ({storefront}) not found"
    )))
}

pub fn search(account: &Account, term: &str, limit: u32, platform: &str) -> Result<Vec<App>> {
    let country = country_code_from_storefront(&account.store_front)?;
    let url = format!(
        "{ITUNES_SEARCH}?entity={}&limit={}&media=software&term={}&country={}",
        search_entity(platform),
        limit,
        url_encode(term),
        country
    );
    let res = http::send(Request::new("GET", &url))
        .map_err(|e| StoreError::Other(format!("search: {e}")))?;
    if res.status != 200 {
        return Err(StoreError::Other(format!("search: HTTP {}", res.status)));
    }
    let text = String::from_utf8_lossy(&res.body);
    let doc = json::parse(&text).map_err(|e| StoreError::Other(format!("search json: {e}")))?;
    let mut apps = Vec::new();
    if let Some(results) = doc.get("results").and_then(|v| v.as_array()) {
        for item in results {
            let app = App::from_search_json(item);
            if app.id != 0 {
                apps.push(app);
            }
        }
    }
    Ok(apps)
}

pub fn lookup(account: &Account, bundle_id: &str, platform: &str) -> Result<App> {
    let country = country_code_from_storefront(&account.store_front)?;
    let url = format!(
        "{ITUNES_LOOKUP}?entity={}&limit=1&media=software&bundleId={}&country={}",
        lookup_entity(platform),
        url_encode(bundle_id),
        country
    );
    let res = http::send(Request::new("GET", &url))
        .map_err(|e| StoreError::Other(format!("lookup: {e}")))?;
    if res.status != 200 {
        return Err(StoreError::Other(format!("lookup: HTTP {}", res.status)));
    }
    let text = String::from_utf8_lossy(&res.body);
    let doc = json::parse(&text).map_err(|e| StoreError::Other(format!("lookup json: {e}")))?;
    let results = doc
        .get("results")
        .and_then(|v| v.as_array())
        .ok_or(StoreError::AppNotFound)?;
    let app = results
        .iter()
        .map(App::from_search_json)
        .find(|a| a.id != 0)
        .ok_or(StoreError::AppNotFound)?;
    Ok(app)
}

pub fn lookup_by_id(account: &Account, app_id: i64, platform: &str) -> Result<App> {
    let country = country_code_from_storefront(&account.store_front)?;
    let url = format!(
        "{ITUNES_LOOKUP}?entity={}&limit=1&media=software&id={}&country={}",
        lookup_entity(platform),
        app_id,
        country
    );
    let res = http::send(Request::new("GET", &url))
        .map_err(|e| StoreError::Other(format!("lookup: {e}")))?;
    if res.status != 200 {
        return Err(StoreError::Other(format!("lookup: HTTP {}", res.status)));
    }
    let text = String::from_utf8_lossy(&res.body);
    let doc = json::parse(&text).map_err(|e| StoreError::Other(format!("lookup json: {e}")))?;
    let results = doc
        .get("results")
        .and_then(|v| v.as_array())
        .ok_or(StoreError::AppNotFound)?;
    results
        .iter()
        .map(App::from_search_json)
        .find(|a| a.id != 0)
        .ok_or(StoreError::AppNotFound)
}

// ── purchase ──────────────────────────────────────────────────────────────

fn buy_url(account: &Account, path: &str, guid: &str) -> String {
    let prefix = if account.pod.is_empty() {
        String::new()
    } else {
        format!("p{}-", account.pod)
    };
    format!("https://{prefix}{BUY_DOMAIN}{path}?guid={guid}")
}

pub fn purchase(account: &Account, app: &App, guid: &str, arcade_fallback: bool) -> Result<()> {
    if app.price > 0.0 {
        return Err(StoreError::PaidApp);
    }
    match purchase_with_params(account, app, guid, PRICING_APPSTORE) {
        Err(StoreError::TemporarilyUnavailable) if arcade_fallback => {
            purchase_with_params(account, app, guid, PRICING_ARCADE)
        }
        other => other,
    }
}

fn purchase_with_params(account: &Account, app: &App, guid: &str, pricing: &str) -> Result<()> {
    let mut payload = Plist::dict();
    payload.set("appExtVrsId", Plist::string("0"));
    payload.set("hasAskedToFulfillPreorder", Plist::string("true"));
    payload.set("buyWithoutAuthorization", Plist::string("true"));
    payload.set("hasDoneAgeCheck", Plist::string("true"));
    payload.set("guid", Plist::string(guid));
    payload.set("needDiv", Plist::string("0"));
    payload.set("origPage", Plist::string(format!("Software-{}", app.id)));
    payload.set("origPageLocation", Plist::string("Buy"));
    payload.set("price", Plist::string("0"));
    payload.set("pricingParameters", Plist::string(pricing));
    payload.set("productType", Plist::string("C"));
    payload.set("salableAdamId", Plist::Integer(app.id));

    let body = plist::to_xml(&payload).into_bytes();
    let res = http::send(
        Request::new("POST", &buy_url(account, PATH_PURCHASE, guid))
            .header("Content-Type", "application/x-apple-plist")
            .header("iCloud-DSID", &account.directory_services_id)
            .header("X-Dsid", &account.directory_services_id)
            .header("X-Apple-Store-Front", &account.store_front)
            .header("X-Token", &account.password_token)
            .plist_body(body),
    )
    .map_err(|e| StoreError::Other(format!("purchase: {e}")))?;

    let doc = plist::parse_xml(&res.body)
        .map_err(|e| StoreError::Other(format!("purchase parse (HTTP {}): {e}", res.status)))?;
    let failure_type = doc
        .get("failureType")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let customer_message = doc
        .get("customerMessage")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let jingle = doc
        .get("jingleDocType")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let status = doc.get("status").and_then(|v| v.as_i64()).unwrap_or(-1);

    if failure_type == FAILURE_TEMPORARILY_UNAVAILABLE {
        return Err(StoreError::TemporarilyUnavailable);
    }
    if customer_message == MSG_SUBSCRIPTION_REQUIRED {
        return Err(StoreError::SubscriptionRequired);
    }
    if failure_type == FAILURE_PASSWORD_TOKEN_EXPIRED
        || failure_type == FAILURE_SIGN_IN_REQUIRED
        || failure_type == FAILURE_DEVICE_VERIFICATION_FAILED
        || customer_message == MSG_PASSWORD_CHANGED
    {
        return Err(StoreError::PasswordTokenExpired);
    }
    if failure_type == FAILURE_LICENSE_ALREADY_EXISTS {
        return Err(StoreError::LicenseAlreadyExists);
    }
    if !failure_type.is_empty() {
        return Err(StoreError::Other(if customer_message.is_empty() {
            "something went wrong".into()
        } else {
            customer_message.to_string()
        }));
    }
    if res.status == 500 {
        // Apple quirk: 500 on repeat purchase of an owned item.
        return Err(StoreError::LicenseAlreadyExists);
    }
    if jingle != "purchaseSuccess" || status != 0 {
        return Err(StoreError::Other("failed to purchase app".into()));
    }
    Ok(())
}

// ── download info (shared by download / list-versions / version metadata) ──

#[derive(Clone, Debug, Default)]
pub struct DownloadInfo {
    pub url: String,
    pub sinfs: Vec<Sinf>,
    pub metadata: Plist,
    pub version: String,
}

/// FairPlay license record as Apple returns it; `id`/`dp_info` are part of
/// the wire format even though the mobile path only consumes `data`.
#[allow(dead_code)]
#[derive(Clone, Debug, Default)]
pub struct Sinf {
    pub id: i64,
    pub data: Vec<u8>,
    pub dp_info: Vec<u8>,
}

fn fetch_download_info(
    account: &Account,
    app_id: i64,
    guid: &str,
    external_version_id: &str,
) -> Result<DownloadInfo> {
    let mut payload = Plist::dict();
    payload.set("creditDisplay", Plist::string(""));
    payload.set("guid", Plist::string(guid));
    payload.set("salableAdamId", Plist::Integer(app_id));
    payload.set("serialNumber", Plist::string("0"));
    if !external_version_id.is_empty() {
        payload.set("externalVersionId", Plist::string(external_version_id));
    }
    let body = plist::to_xml(&payload).into_bytes();
    let res = http::send(
        Request::new("POST", &buy_url(account, PATH_DOWNLOAD, guid))
            .header("Content-Type", "application/x-apple-plist")
            .header("iCloud-DSID", &account.directory_services_id)
            .header("X-Dsid", &account.directory_services_id)
            .plist_body(body),
    )
    .map_err(|e| StoreError::Other(format!("download info: {e}")))?;

    let doc = plist::parse_xml(&res.body).map_err(|e| {
        StoreError::Other(format!("download info parse (HTTP {}): {e}", res.status))
    })?;
    let failure_type = doc
        .get("failureType")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let customer_message = doc
        .get("customerMessage")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if failure_type == FAILURE_PASSWORD_TOKEN_EXPIRED
        || failure_type == FAILURE_SIGN_IN_REQUIRED
        || failure_type == FAILURE_DEVICE_VERIFICATION_FAILED
    {
        return Err(StoreError::PasswordTokenExpired);
    }
    if failure_type == FAILURE_LICENSE_NOT_FOUND {
        return Err(StoreError::LicenseRequired);
    }
    if !failure_type.is_empty() {
        return Err(StoreError::Other(if customer_message.is_empty() {
            format!("download info: {failure_type}")
        } else {
            customer_message.to_string()
        }));
    }

    let items = doc
        .get("songList")
        .and_then(|v| v.as_array())
        .ok_or_else(|| StoreError::Other("download info: no songList".into()))?;
    let item = items
        .first()
        .ok_or_else(|| StoreError::Other("download info: empty songList".into()))?;

    let url = item
        .get("URL")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let mut sinfs = Vec::new();
    if let Some(list) = item.get("sinfs").and_then(|v| v.as_array()) {
        for entry in list {
            sinfs.push(Sinf {
                id: entry.get("id").and_then(|v| v.as_i64()).unwrap_or(0),
                data: entry
                    .get("sinf")
                    .and_then(|v| v.as_data())
                    .unwrap_or(&[])
                    .to_vec(),
                dp_info: entry
                    .get("dpInfo")
                    .and_then(|v| v.as_data())
                    .unwrap_or(&[])
                    .to_vec(),
            });
        }
    }
    let metadata = item.get("metadata").cloned().unwrap_or_else(Plist::dict);
    let version = metadata
        .get("bundleShortVersionString")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    if url.is_empty() {
        return Err(StoreError::Other("download info: no URL".into()));
    }
    Ok(DownloadInfo {
        url,
        sinfs,
        metadata,
        version,
    })
}

// ── download ──────────────────────────────────────────────────────────────

pub struct DownloadOutput {
    pub destination: String,
    #[allow(dead_code)]
    pub sinfs: Vec<Sinf>,
}

/// Stream the package to `output` (file path or directory) with a progress
/// callback, then replicate the sinf sidecars into the IPA.
pub fn download(
    account: &Account,
    app: &App,
    output: &str,
    external_version_id: &str,
    guid: &str,
    progress: &mut dyn FnMut(u64, u64),
) -> Result<DownloadOutput> {
    let info = fetch_download_info(account, app.id, guid, external_version_id)?;

    let destination = resolve_destination(app, &info.version, output)?;
    let tmp_path = format!("{}.tmp", destination);

    // Stream to disk.
    let mut file = std::fs::File::create(&tmp_path)
        .map_err(|e| StoreError::Other(format!("create {tmp_path}: {e}")))?;
    let mut sink = std::io::BufWriter::new(&mut file);
    let res = http::send(
        Request::new("GET", &info.url)
            .with_sink(&mut sink)
            .with_progress(progress),
    )
    .map_err(|e| {
        let _ = std::fs::remove_file(&tmp_path);
        StoreError::Other(format!("download: {e}"))
    })?;
    drop(sink);
    if res.status != 200 {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(StoreError::Other(format!("download: HTTP {}", res.status)));
    }
    drop(file);

    // Replicate: copy entries, inject iTunesMetadata.plist and the sinfs.
    // On failure keep the .tmp file for offline debugging.
    let patched = super::ipa::replicate(&tmp_path, &destination, &info, account).map_err(|e| {
        let _ = std::fs::rename(&tmp_path, format!("{}.badzip", destination));
        StoreError::Other(format!("replicate: {e}"))
    })?;
    if !patched {
        // No bundle found (rare): move as-is.
        std::fs::rename(&tmp_path, &destination)
            .map_err(|e| StoreError::Other(format!("rename: {e}")))?;
    } else {
        let _ = std::fs::remove_file(&tmp_path);
    }

    Ok(DownloadOutput {
        destination,
        sinfs: info.sinfs,
    })
}

fn resolve_destination(app: &App, version: &str, output: &str) -> Result<String> {
    let mut parts = Vec::new();
    if !app.bundle_id.is_empty() {
        parts.push(app.bundle_id.clone());
    }
    if app.id != 0 {
        parts.push(app.id.to_string());
    }
    if !version.is_empty() {
        parts.push(version.to_string());
    }
    let file = format!("{}.ipa", parts.join("_"));
    if output.is_empty() {
        let cwd = std::env::current_dir().map_err(|e| StoreError::Other(format!("cwd: {e}")))?;
        return Ok(cwd.join(file).display().to_string());
    }
    let path = std::path::Path::new(output);
    if path.is_dir() {
        Ok(path.join(file).display().to_string())
    } else {
        Ok(output.to_string())
    }
}

// ── list versions / version metadata ──────────────────────────────────────

pub struct ListVersionsOutput {
    pub external_version_identifiers: Vec<String>,
    #[allow(dead_code)]
    pub latest_external_version_id: String,
}

pub fn list_versions(account: &Account, app_id: i64, guid: &str) -> Result<ListVersionsOutput> {
    let info = fetch_download_info(account, app_id, guid, "")?;
    let ids = info
        .metadata
        .get("softwareVersionExternalIdentifiers")
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            StoreError::Other("no softwareVersionExternalIdentifiers in metadata".into())
        })?;
    let identifiers: Vec<String> = ids
        .iter()
        .map(|v| match v {
            Plist::Integer(i) => i.to_string(),
            Plist::String(s) => s.clone(),
            _ => String::new(),
        })
        .collect();
    let latest = info
        .metadata
        .get("softwareVersionExternalIdentifier")
        .map(|v| match v {
            Plist::Integer(i) => i.to_string(),
            Plist::String(s) => s.clone(),
            _ => String::new(),
        })
        .unwrap_or_default();
    Ok(ListVersionsOutput {
        external_version_identifiers: identifiers,
        latest_external_version_id: latest,
    })
}

pub struct VersionMetadata {
    pub display_version: String,
    pub release_date: String,
}

/// Read the display version + release date from the IPA's Info.plist
/// without downloading the whole package: HTTP range requests over the
/// zip central directory, then the one entry we need.
pub fn get_version_metadata(
    account: &Account,
    app_id: i64,
    guid: &str,
    external_version_id: &str,
) -> Result<VersionMetadata> {
    let info = fetch_download_info(account, app_id, guid, external_version_id)?;
    let (plist_data, modified) = super::ipa::fetch_info_plist(&info.url)
        .map_err(|e| StoreError::Other(format!("version metadata: {e}")))?;
    let doc = plist::parse_binary(&plist_data)
        .or_else(|_| plist::parse_xml(&plist_data))
        .map_err(|e| StoreError::Other(format!("Info.plist parse: {e}")))?;
    let version = ["CFBundleShortVersionString", "bundleShortVersionString"]
        .iter()
        .find_map(|key| doc.get(key).and_then(|v| v.as_str()))
        .unwrap_or("");
    let date = ["releaseDate", "ReleaseDate"]
        .iter()
        .find_map(|key| doc.get(key).and_then(|v| v.as_str()))
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            // majd falls back to the zip entry's modified time, UTC.
            let t = modified;
            let days = t.div_euclid(86_400);
            let secs = t.rem_euclid(86_400);
            let z = days + 719_468;
            let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
            let doe = z - era * 146_097;
            let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
            let y = yoe + era * 400;
            let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
            let mp = (5 * doy + 2) / 153;
            let d = doy - (153 * mp + 2) / 5 + 1;
            let m = if mp < 10 { mp + 3 } else { mp - 9 };
            let y = if m <= 2 { y + 1 } else { y };
            format!(
                "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
                secs / 3600,
                (secs % 3600) / 60,
                secs % 60
            )
        });
    Ok(VersionMetadata {
        display_version: version.to_string(),
        release_date: date,
    })
}

// ── owned apps (purchase history via DAAP) ────────────────────────────────

pub struct OwnedAppsOutput {
    pub total: usize,
    pub apps: Vec<App>,
}

/// Purchase history: DAAP login → update → items; the update and items
/// bodies are SAP-signed (the two requests Apple gates with the action
/// signature beyond login).
pub fn owned_apps(
    account: &Account,
    guid: &str,
    signer: &mut Signer,
    page: u32,
    limit: u32,
) -> Result<OwnedAppsOutput> {
    let login_res = http::send(
        Request::new("POST", &format!("{PURCHASE_DAAP_BASE}/login"))
            .header("Accept", "*/*")
            .header("Accept-Language", "en-us")
            .header("Client-Cloud-DAAP-Request-Reason", "5")
            .header("Client-Cloud-Purchase-Daap-Version", "1.1/Configurator-2.0")
            .header("Client-DAAP-Version", "3.12")
            .header("iCloud-DSID", &account.directory_services_id)
            .header("X-Apple-Store-Front", &account.store_front)
            .header("X-Dsid", &account.directory_services_id)
            .header("X-Guid", guid)
            .header("X-Token", &account.password_token),
    )
    .map_err(|e| StoreError::Other(format!("daap login: {e}")))?;
    if login_res.status != 200 {
        return Err(StoreError::Other(format!(
            "daap login: HTTP {}",
            login_res.status
        )));
    }
    super::dmap::status_ok(&login_res.body, "daap login").map_err(StoreError::Other)?;
    let session_id = super::dmap::first_uint(&login_res.body, "mlid")
        .ok_or_else(|| StoreError::Other("daap login: no mlid".into()))?;

    let query = "('com.apple.itunes.extended\\-media\\-kind:131072')";
    let update_body = format!("session-id={session_id}&revision-number=(null)&query={query}");
    let (name, value) = signer
        .sign_header(update_body.as_bytes())
        .map_err(|e| StoreError::Other(format!("sign update: {e}")))?;
    let update_res = http::send(
        Request::new("POST", &format!("{PURCHASE_DAAP_BASE}/update"))
            .header(&name, &value)
            .header_vec(&super::dmap::daap_headers(account, guid))
            .form_body(update_body.into_bytes()),
    )
    .map_err(|e| StoreError::Other(format!("daap update: {e}")))?;
    if update_res.status != 200 {
        return Err(StoreError::Other(format!(
            "daap update: HTTP {}",
            update_res.status
        )));
    }
    super::dmap::status_ok(&update_res.body, "daap update").map_err(StoreError::Other)?;
    let revision = super::dmap::first_uint(&update_res.body, "musr")
        .ok_or_else(|| StoreError::Other("daap update: no musr".into()))?;

    let items_body = super::dmap::items_body(session_id as u32, revision as u32, query);
    let (name, value) = signer
        .sign_header(&items_body)
        .map_err(|e| StoreError::Other(format!("sign items: {e}")))?;
    let items_res = http::send(
        Request::new(
            "POST",
            &format!("{PURCHASE_DAAP_BASE}/databases/{revision}/items"),
        )
        .header(&name, &value)
        .header_vec(&super::dmap::daap_headers(account, guid))
        .header("Content-Type", "application/x-dmap-tagged")
        .body_bytes(items_body),
    )
    .map_err(|e| StoreError::Other(format!("daap items: {e}")))?;
    if items_res.status != 200 {
        return Err(StoreError::Other(format!(
            "daap items: HTTP {}",
            items_res.status
        )));
    }

    super::dmap::status_ok(&items_res.body, "daap items").map_err(StoreError::Other)?;
    let mut apps = super::dmap::parse_owned_apps(&items_res.body);
    // Sort newest first, then page.
    apps.sort_by(|a, b| b.purchase_date.cmp(&a.purchase_date));
    let total = apps.len();
    let start = ((page - 1).saturating_mul(limit) as usize).min(total);
    let end = (start + limit as usize).min(total);
    Ok(OwnedAppsOutput {
        total,
        apps: apps[start..end].to_vec(),
    })
}

/// visionOS search (majd searchVisionOS): the storefront search page's
/// serialized-server-data yields app ids; iTunes lookup hydrates them.
pub fn search_visionos(account: &Account, term: &str, limit: i64) -> Result<Vec<App>> {
    let country = country_code_from_storefront(&account.store_front)?;
    let url = format!(
        "https://apps.apple.com/{}/vision/search?term={}",
        url_encode(&country.to_lowercase()),
        url_encode(term)
    );
    let res = http::send(Request::new("GET", &url))
        .map_err(|e| StoreError::Other(format!("visionOS search request failed: {e}")))?;
    if res.status != 200 {
        // majd: NewErrorWithMetadata — the status rides as metadata, not text.
        return Err(StoreError::Other("visionOS search request failed".into()));
    }
    let apps = storefront_vision_apps(&res.body, limit)?;
    if apps.is_empty() {
        return Ok(Vec::new());
    }
    let ids: Vec<String> = apps.iter().map(|a| a.id.to_string()).collect();
    let hydrated = lookup_ids(account, &ids, "visionos")?;
    let by_id: std::collections::HashMap<i64, App> =
        hydrated.into_iter().map(|a| (a.id, a)).collect();
    Ok(apps
        .into_iter()
        .map(|a| by_id.get(&a.id).cloned().unwrap_or(a))
        .collect())
}

/// Walk the storefront search page's shelves for AppSearchResult lockups
/// carrying a vision purchaseConfiguration (majd storefrontVisionApps).
fn storefront_vision_apps(body: &[u8], limit: i64) -> Result<Vec<App>> {
    let text = String::from_utf8_lossy(body);
    let script = extract_serialized_server_data(&text).ok_or_else(|| {
        StoreError::Other("failed to parse visionOS search results: serialized server data was not found".into())
    })?;
    let doc = json::parse(script).map_err(|e| {
        StoreError::Other(format!("failed to decode serialized server data: {e}"))
    })?;
    if limit <= 0 {
        return Ok(Vec::new());
    }
    let limit = limit.min(12);
    let mut apps: Vec<App> = Vec::new();
    let mut seen: std::collections::HashSet<i64> = std::collections::HashSet::new();
    if let Some(top) = doc.get("data").and_then(|d| d.as_array()) {
        for page_data in top {
            let Some(shelves) = page_data
                .get("data")
                .and_then(|d| d.get("shelves"))
                .and_then(|s| s.as_array())
            else {
                continue;
            };
            for shelf in shelves {
                let Some(items) = shelf.get("items").and_then(|i| i.as_array()) else {
                    continue;
                };
                for item in items {
                    if item.get("$kind").and_then(|k| k.as_str()) != Some("AppSearchResult") {
                        continue;
                    }
                    let Some(lockup) = item.get("lockup") else { continue };
                    let id = lockup.get("adamId").and_then(|v| v.as_i64()).unwrap_or(0);
                    if id == 0 || !seen.insert(id) {
                        continue;
                    }
                    if !contains_vision_purchase_config(item, id) {
                        continue;
                    }
                    apps.push(App {
                        id,
                        bundle_id: lockup
                            .get("bundleId")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        name: lockup
                            .get("title")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        ..App::default()
                    });
                    if apps.len() as i64 == limit {
                        return Ok(apps);
                    }
                }
            }
        }
    }
    Ok(apps)
}

fn contains_vision_purchase_config(item: &json::Json, app_id: i64) -> bool {
    find_vision_external(item, app_id).is_some()
}

/// iTunes lookup by explicit id list (majd lookupIDsRequest).
pub fn lookup_ids(account: &Account, ids: &[String], platform: &str) -> Result<Vec<App>> {
    let country = country_code_from_storefront(&account.store_front)?;
    let url = format!(
        "{ITUNES_LOOKUP}?entity={}&id={}&country={}",
        lookup_entity(platform),
        ids.join(","),
        country
    );
    let res = http::send(Request::new("GET", &url))
        .map_err(|e| StoreError::Other(format!("visionOS metadata request failed: {e}")))?;
    if res.status != 200 {
        return Err(StoreError::Other(format!(
            "visionOS metadata request failed: HTTP {}",
            res.status
        )));
    }
    let text = String::from_utf8_lossy(&res.body);
    let doc = json::parse(&text)
        .map_err(|e| StoreError::Other(format!("visionOS metadata json: {e}")))?;
    let mut apps = Vec::new();
    if let Some(results) = doc.get("results").and_then(|v| v.as_array()) {
        for item in results {
            let app = App::from_search_json(item);
            if app.id != 0 {
                apps.push(app);
            }
        }
    }
    Ok(apps)
}

// ── platform version lookup (MDM): latest external version id for tvOS /
// visionOS downloads without an explicit `--external-version-id` ──────────

/// MZStorePlatform lookup (the MDM flow): returns the first offer's
/// external version id, falling back to `appExtVrsId` in its buy params.
pub fn lookup_latest_external_version_id(
    app_id: i64,
    country: &str,
    metadata_platform: &str,
) -> Result<String> {
    let url = format!(
        "https://uclient-api.itunes.apple.com/WebObjects/MZStorePlatform.woa/wa/lookup\
         ?version=2&id={app_id}&p=mdm-lockup&caller=MDM&platform={metadata_platform}\
         &cc={}&l=en",
        url_encode(country)
    );
    let res = http::send(Request::new("GET", &url))
        .map_err(|e| StoreError::Other(format!("platform version lookup: {e}")))?;
    if res.status != 200 {
        return Err(StoreError::Other(format!(
            "platform version lookup request failed: HTTP {}",
            res.status
        )));
    }
    let text = String::from_utf8_lossy(&res.body);
    let doc = json::parse(&text)
        .map_err(|e| StoreError::Other(format!("platform version lookup json: {e}")))?;
    let key = app_id.to_string();
    let item = doc
        .get("results")
        .and_then(|v| v.get(&key))
        .ok_or_else(|| StoreError::Other("platform version lookup returned no app".into()))?;
    let offers = item
        .get("offers")
        .and_then(|v| v.as_array())
        .ok_or_else(|| StoreError::Other("platform version lookup returned no offers".into()))?;
    let offer = offers
        .first()
        .ok_or_else(|| StoreError::Other("platform version lookup returned no offers".into()))?;
    let mut external = offer
        .get("version")
        .and_then(|v| v.get("externalId"))
        .and_then(|v| v.as_number().or_else(|| v.as_str()))
        .unwrap_or_default()
        .to_string();
    if external.is_empty() {
        let buy = offer
            .get("buyParams")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        for pair in buy.split('&') {
            if let Some(value) = pair.strip_prefix("appExtVrsId=") {
                external = value.to_string();
            }
        }
    }
    if external.is_empty() {
        return Err(StoreError::Other(
            "platform version lookup returned no external version id".into(),
        ));
    }
    Ok(external)
}

/// visionOS variant: the storefront HTML carries the version in a
/// `serialized-server-data` script's purchaseConfiguration buy params.
pub fn lookup_latest_visionos_external_version_id(app_id: i64, country: &str) -> Result<String> {
    let url = format!(
        "https://apps.apple.com/{}/app/id{}?platform=vision",
        url_encode(&country.to_lowercase()),
        app_id
    );
    let res = http::send(Request::new("GET", &url))
        .map_err(|e| StoreError::Other(format!("visionOS version lookup: {e}")))?;
    if res.status != 200 {
        return Err(StoreError::Other(format!(
            "visionOS version lookup request failed: HTTP {}",
            res.status
        )));
    }
    let external = vision_external_version_id(&res.body, app_id)
        .ok_or_else(|| StoreError::Other("visionOS purchase configuration was not found".into()))?;
    if external.is_empty() {
        return Err(StoreError::Other(
            "visionOS purchase configuration has no external version id".into(),
        ));
    }
    Ok(external)
}

/// Extract the `serialized-server-data` JSON and walk it for a vision
/// purchaseConfiguration whose `salableAdamId` matches the app id.
/// majd's serializedServerData: the JSON inside the
/// `<script id="serialized-server-data">…</script>` tag.
fn extract_serialized_server_data(text: &str) -> Option<&str> {
    let marker = text.find("id=\"serialized-server-data\"").or_else(|| {
        let cut = text.find("id='serialized-server-data'")?;
        Some(cut)
    })?;
    text[..marker].rfind("<script")?;
    let content_start = marker + text[marker..].find('>')?;
    let content_end = text[content_start..].find("</script>")? + content_start;
    Some(text[content_start + 1..content_end].trim())
}

fn vision_external_version_id(body: &[u8], app_id: i64) -> Option<String> {
    let text = String::from_utf8_lossy(body);
    let script = extract_serialized_server_data(&text)?;
    let doc = json::parse(script).ok()?;
    find_vision_external(&doc, app_id)
}

/// Recursive walk matching majd's findVisionExternalVersionID: any nested
/// object with purchaseConfiguration{metricsPlatformDisplayStyle=vision,
/// appPlatforms∋vision, buyParams.salableAdamId=appID} yields its
/// appExtVrsId.
fn find_vision_external(doc: &json::Json, app_id: i64) -> Option<String> {
    if let Some(config) = doc
        .get("purchaseConfiguration")
        .and_then(|c| vision_config_external(c, app_id))
        && !config.is_empty()
    {
        return Some(config);
    }
    match doc {
        json::Json::Array(items) => {
            for item in items {
                if let Some(found) = find_vision_external(item, app_id)
                    && !found.is_empty()
                {
                    return Some(found);
                }
            }
        }
        json::Json::Object(entries) => {
            for (_, value) in entries {
                if let Some(found) = find_vision_external(value, app_id)
                    && !found.is_empty()
                {
                    return Some(found);
                }
            }
        }
        _ => {}
    }
    None
}

fn vision_config_external(config: &json::Json, app_id: i64) -> Option<String> {
    if config
        .get("metricsPlatformDisplayStyle")
        .and_then(|v| v.as_str())
        != Some("vision")
    {
        return None;
    }
    let platforms = config.get("appPlatforms")?;
    let mut is_vision = false;
    if let Some(items) = platforms.as_array() {
        for p in items {
            if p.as_str() == Some("vision") {
                is_vision = true;
            }
        }
    }
    if !is_vision {
        return None;
    }
    let buy = config
        .get("buyParams")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())?;
    let mut external = String::new();
    let mut salable = String::new();
    for pair in buy.split('&') {
        if let Some(v) = pair.strip_prefix("salableAdamId=") {
            salable = v.to_string();
        }
        if let Some(v) = pair.strip_prefix("appExtVrsId=") {
            external = v.to_string();
        }
    }
    if salable != app_id.to_string() {
        return None;
    }
    Some(external)
}

// ── URL encoding ─────────────────────────────────────────────────────────

pub fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push_str("%20"),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
// silence unused warnings for items kept for CLI parity
#[allow(unused)]
fn _ui_stub() {}
