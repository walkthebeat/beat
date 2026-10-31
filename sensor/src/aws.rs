//! `--attest aws`: the sensor asks AWS STS for a signed OIDC token naming this EC2 instance (outbound identity
//! federation, docs/security.md H4), at the moment it enrols, so the token is never older than the request.
//!
//! The instance metadata service (IMDSv2) gives the region and the instance role's temporary credentials; with them
//! the sensor signs (SigV4) a GetWebIdentityToken call to STS in its region. STS answers with an RS256 JWT from the
//! account's own issuer, with the account, role and instance ARN under the claim https://sts.amazonaws.com/; the
//! org's trust policy checks those (docs/security.md H13). The role needs sts:GetWebIdentityToken and the account
//! outbound federation enabled; nothing else. Credentials are used for this one call and not kept.

use std::time::Duration;

use anyhow::{bail, Context};
use serde_json::Value;
use sha2::{Digest, Sha256};

const IMDS: &str = "http://169.254.169.254/latest";
const LIFETIME_S: u32 = 300;  // STS's shortest is 60: enough for one enrolment, and the default

/// The JWT, for `audience` (the policy's, beat-enroll by default).
pub fn identity_token(audience: &str) -> anyhow::Result<String> {
    let md = |path: &str, t: &str| -> anyhow::Result<String> {
        ureq::get(&format!("{IMDS}/{path}")).set("X-aws-ec2-metadata-token", t)
            .timeout(Duration::from_secs(5)).call()?.into_string().map_err(Into::into)
    };
    let t = ureq::put(&format!("{IMDS}/api/token")).set("X-aws-ec2-metadata-token-ttl-seconds", "60")
        .timeout(Duration::from_secs(5)).call()
        .context("--attest aws: no EC2 instance metadata here (IMDSv2)")?.into_string()?;
    let region = md("meta-data/placement/region", &t)?;
    let role = md("meta-data/iam/security-credentials/", &t)
        .context("--attest aws: this instance has no IAM role (instance profile)")?;
    let creds: Value = serde_json::from_str(&md(&format!("meta-data/iam/security-credentials/{}", role.trim()), &t)?)?;
    let get = |k: &str| creds[k].as_str().with_context(|| format!("instance credentials without {k}"));

    let host = format!("sts.{region}.amazonaws.com");
    let body = format!("Action=GetWebIdentityToken&Version=2011-06-15&Audience.member.1={}&SigningAlgorithm=RS256\
                        &DurationSeconds={LIFETIME_S}", form(audience));
    let now = crate::unix_now();
    let auth = authorization(get("AccessKeyId")?, get("SecretAccessKey")?, get("Token")?, &region, &host, &body, now);
    let r = ureq::post(&format!("https://{host}/"))
        .set("Content-Type", CONTENT_TYPE)
        .set("X-Amz-Date", &amz_date(now))
        .set("X-Amz-Security-Token", get("Token")?)
        .set("Authorization", &auth)
        .timeout(Duration::from_secs(15)).send_string(&body);
    let xml = match r {
        Ok(r) => r.into_string()?,
        Err(ureq::Error::Status(code, r)) => {
            let xml = r.into_string().unwrap_or_default();
            bail!("--attest aws: STS refused ({code}): {} (the role needs sts:GetWebIdentityToken; the account, \
                   aws iam enable-outbound-web-identity-federation)", between(&xml, "Message").unwrap_or(&xml))
        }
        Err(e) => bail!("--attest aws: {host} is not answering: {e}"),
    };
    between(&xml, "WebIdentityToken").map(String::from).context("--attest aws: no token in STS's answer")
}

const CONTENT_TYPE: &str = "application/x-www-form-urlencoded; charset=utf-8";

fn between<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    let start = xml.find(&format!("<{tag}>"))? + tag.len() + 2;
    Some(&xml[start..start + xml[start..].find(&format!("</{tag}>"))?])
}

/// application/x-www-form-urlencoded, as SigV4 wants it: everything but A-Z a-z 0-9 - _ . ~ as %XX.
fn form(s: &str) -> String {
    s.bytes().map(|b| match b {
        b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
        _ => format!("%{b:02X}"),
    }).collect()
}

/// The Authorization header of a SigV4-signed POST of `body` to STS (service "sts") at `host`.
fn authorization(key_id: &str, secret: &str, token: &str, region: &str, host: &str, body: &str, now: i64) -> String {
    let date = amz_date(now);
    let scope = format!("{}/{region}/sts/aws4_request", &date[..8]);
    let signed = "content-type;host;x-amz-date;x-amz-security-token";
    let request = format!("POST\n/\n\ncontent-type:{CONTENT_TYPE}\nhost:{host}\nx-amz-date:{date}\n\
                           x-amz-security-token:{token}\n\n{signed}\n{}", hex(&Sha256::digest(body)));
    let to_sign = format!("AWS4-HMAC-SHA256\n{date}\n{scope}\n{}", hex(&Sha256::digest(request)));
    let signature = hex(&hmac(&signing_key(secret, &date[..8], region, "sts"), to_sign.as_bytes()));
    format!("AWS4-HMAC-SHA256 Credential={key_id}/{scope}, SignedHeaders={signed}, Signature={signature}")
}

fn signing_key(secret: &str, day: &str, region: &str, service: &str) -> [u8; 32] {
    [day, region, service, "aws4_request"].iter()
        .fold(format!("AWS4{secret}").into_bytes(), |k, part| hmac(&k, part.as_bytes()).to_vec())
        .try_into().unwrap()
}

/// HMAC-SHA256 (RFC 2104), on the sha2 the sensor has already.
fn hmac(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let pad = |x: u8| k.iter().map(|b| b ^ x).collect::<Vec<u8>>();
    let inner = Sha256::new().chain_update(pad(0x36)).chain_update(msg).finalize();
    Sha256::new().chain_update(pad(0x5c)).chain_update(inner).finalize().into()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// 20270115T080000Z (UTC) from Unix seconds.
fn amz_date(now: i64) -> String {
    let (days, secs) = (now.div_euclid(86400), now.rem_euclid(86400));
    // days since 1970-01-01 to a civil date (H. Hinnant's days_from_civil, inverted)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}{m:02}{d:02}T{:02}{:02}{:02}Z", secs / 3600, secs % 3600 / 60, secs % 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates() {
        assert_eq!(amz_date(0), "19700101T000000Z");
        assert_eq!(amz_date(1_800_000_000), "20270115T080000Z");
        assert_eq!(amz_date(951_782_400), "20000229T000000Z");
    }

    #[test]
    fn hmac_rfc4231_case_2() {
        assert_eq!(hex(&hmac(b"Jefe", b"what do ya want for nothing?")),
                   "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    }

    #[test]
    fn signing_key_from_the_aws_example() {
        // docs.aws.amazon.com, "Examples of how to derive a signing key for Signature Version 4"
        assert_eq!(hex(&signing_key("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "20150830", "us-east-1", "iam")),
                   "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9");
    }

    #[test]
    fn the_answer_and_the_form() {
        assert_eq!(between("<R><WebIdentityToken>eyJ.a.b</WebIdentityToken></R>", "WebIdentityToken"), Some("eyJ.a.b"));
        assert_eq!(form("beat-enroll"), "beat-enroll");
        assert_eq!(form("a b/c"), "a%20b%2Fc");
    }
}
