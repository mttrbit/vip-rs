use {
    reqwest::blocking::Client,
    reqwest::header::{HeaderValue, REFERER, USER_AGENT},
    serde::{de::DeserializeOwned, Deserialize},
    std::{thread::sleep, time::Duration},
};

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync + 'static>>;

#[derive(Deserialize, Debug)]
struct GetGroupCredentialsResponse {
    success: bool,
    data: Data,
}

#[derive(Deserialize, Debug)]
struct Data {
    #[serde(rename = "policyJson")]
    policy_json: Policy,
    credentials: String,
    status: u64,
    #[serde(rename = "statusMsg")]
    status_msg: String,
}

#[derive(Deserialize, Debug)]
struct Policy {
    #[serde(rename = "skipAuthToken")]
    skip_auth_token: bool,
    df: bool,
    mo: bool,
    salt: String,
    #[serde(rename = "RD_ALLOWED")]
    rd_allowed: bool,
    #[serde(rename = "useIASc")]
    use_iasc: bool,
    #[serde(rename = "moFallback")]
    mo_fallback: bool,
    rc: bool,
    #[serde(rename = "MFAPolicy")]
    mfa_policy: Option<String>,
    #[serde(rename = "entIdHashEnabled")]
    ent_id_hash_enabled: bool,
    #[serde(rename = "useAccount")]
    use_account: String,
    risk: bool,
    device: bool,
    #[serde(rename = "canaryThresholds")]
    canary_thresholds: CanaryThresholds,
}

#[derive(Deserialize, Debug)]
struct CanaryThresholds {
    #[serde(rename = "tdUpgrade")]
    td_upgrade: Threshold,
}

#[derive(Deserialize, Debug)]
struct Threshold {
    threshold: u64,
}

#[derive(Deserialize, Debug)]
struct CreatePushNotificationResponse {
    #[serde(rename = "pushTo")]
    push_to: Option<Vec<PushTo>>,
    #[serde(rename = "rdBlocked")]
    rd_blocked: Option<bool>,
    #[serde(rename = "txnId")]
    txn_id: Option<String>,
    #[serde(rename = "type")]
    type_name: String,
}

#[derive(Deserialize, Debug)]
struct PushTo {
    #[serde(rename = "credId")]
    cred_id: String,
    #[serde(rename = "deviceName")]
    device_name: String,
}

#[derive(Deserialize, Debug)]
struct CheckPushNotification {
    #[serde(rename = "type")]
    type_name: String,
    ticket: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct CodeResponse {
    pub success: bool,
    pub ret: Payload,
}

#[derive(Deserialize, Debug)]
pub struct Payload {
    #[serde(rename = "credData")]
    pub cred_data: Option<String>,
    #[serde(rename = "credId")]
    pub cred_id: Option<String>,
    pub status: u64,
    #[serde(rename = "statusMsg")]
    pub status_msg: String,
    pub ticket: String,
}

pub fn fetch_security_code(
    user: &str,
    request_id: &str,
    referer: &'static str,
) -> Result<CodeResponse> {
    let _ = vip_api::<GetGroupCredentialsResponse>(
        "vipuserservices/resources/getGroupCredentials",
        referer,
        &format!(
            "_method=POST&reqData=%7B%22user%22%3A%22{}%22%2C%22isUserIdHashed%22%3A{}%2C%22initCredArray%22%3A%22{}%22%7D",
            user,
            false,
            "null"
        ),
    )?;

    let create_push_notification: CreatePushNotificationResponse = vip_api(
        "vipuserservices/resources/motickets",
        referer,
        &format!(
            "_method=POST&reqData=%7B%22type%22%3A%22push%22%2C%22user%22%3A%22{}%22%2C%22isUserIdHashed%22%3A{}%2C%22requestId%22%3A%22VIPJS_{}%22%2C%22authToken%22%3A{}%2C%22authTokenRequestTime%22%3A{}%2C%22idpUrl%22%3A%22%22%2C%22rpUrlAlias%22%3A%22%22%7D",
            user,
            false,
            request_id,
            "null",
            "null"
        ))?;

    let wait_for_confirmation = |transaction_id: &str| -> Result<CheckPushNotification> {
        let mut response: CheckPushNotification;
        loop {
            response = vip_api(
                "vipuserservices/resources/motickets",
                referer,
                &format!(
                    "_method=GET&reqData=%7B%22transactionId%22%3A%22{}%22%7D",
                    transaction_id
                ),
            )?;

            match response.type_name.as_str() {
                "push-in-progress" => sleep(Duration::from_millis(500)),
                _ => break,
            }
        }

        Ok(response)
    };

    let request_security_code = |user: &str,
                                 request_id: &str,
                                 ticket: &str|
     -> Result<CodeResponse> {
        vip_api(
                    "vipuserservices/resources/provsctickets",
                referer,
                    &format!(
                        "_method=POST&reqData=%7B%22user%22%3A%22{}%22%2C%22isUserIdHashed%22%3A{}%2C%22requestId%22%3A%22VIPJS_{}%22%2C%22code%22%3A%22{}%22%2C%22mobilePushApproved%22%3A{}%2C%22rememberDevice%22%3A{}%2C%22friendlyName%22%3Anull%2C%22credType%22%3Anull%2C%22browser%22%3A%22Firefox+82%22%2C%22os%22%3A%22Mac+OS%22%7D",
                        user,
                        false,
                        request_id,
                        ticket,
                        true,
                        "null"
                    )
                )
    };

    let fetch_security_code = |notification: &CheckPushNotification| -> Result<CodeResponse> {
        match notification.type_name.clone().as_str() {
            "ticket" => {
                let ticket = notification.ticket.as_ref().unwrap();
                request_security_code(user, request_id, ticket)
            }
            _ => Err(format!("state unknwon {:?}", notification.type_name).into()),
        }
    };

    match create_push_notification.type_name.as_str() {
        "can-not-push" => {
            println!("Please enter a security code: ");
            let mut ticket = String::new();
            let _ = std::io::stdin().read_line(&mut ticket)?;
            ticket = ticket.trim_end_matches(|c| c == '\n').to_string();
            request_security_code(user, request_id, &ticket)
        }

        _ => match create_push_notification.txn_id {
            Some(txn_id) => {
                wait_for_confirmation(&txn_id).and_then(|res| fetch_security_code(&res))
            }
            None => Err("TransactionId is missing!".into()),
        },
    }
}

fn vip_api<T: DeserializeOwned>(endpoint: &str, referer: &str, body: &str) -> Result<T> {
    let client = Client::new()
        .post(&format!(
            "https://userservices.vip.symantec.com/{}",
            endpoint
        ))
        .header(
            USER_AGENT,
            HeaderValue::from_static(
                "Mozilla/5.0 (Windows NT 6.1; rv:52.0) Gecko/20100101 Firefox/52.0",
            ),
        )
        .header(
            REFERER,
            HeaderValue::from_bytes(&referer.as_bytes().to_vec())?,
        );
    let response = client.body(body.to_string()).send()?;
    Ok(response.json()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_usage() {
        let user = "john.doe%40example.com";
        let request_id = "yOur12343rEquEstIDHerE";
        let referer = "https:://subdomain.example.com";
        fetch_security_code(user, request_id, referer).unwrap();
    }
}
