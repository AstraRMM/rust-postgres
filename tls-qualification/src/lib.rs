//! Throwaway PKI helpers shared by the fixture generator and the tests that
//! need to sign material at test time (for example a CRL that expires a few
//! seconds after it is loaded). Nothing here is a real credential.

use rcgen::{
    date_time_ymd, BasicConstraints, Certificate, CertificateParams,
    CertificateRevocationListParams, DistinguishedName, DnType, IsCa, KeyIdMethod, KeyPair,
    KeyUsagePurpose, RevocationReason, RevokedCertParams, SerialNumber,
};
use time::OffsetDateTime;

/// Common name of the qualification CA that issues the PostgreSQL fixtures.
pub const CA_A_CN: &str = "qualification CA A";

pub fn name(cn: &str) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::OrganizationName, "AST-2128 qualification");
    dn.push(DnType::CommonName, cn);
    dn
}

/// Parameters of a fixture CA. Re-signing these with the CA's key yields a
/// certificate with the same subject and key, which is all a CRL issuer needs.
pub fn ca_params(cn: &str, serial: Option<u64>) -> CertificateParams {
    let mut params = CertificateParams::default();
    params.distinguished_name = name(cn);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    params.serial_number = serial.map(SerialNumber::from);
    params.not_before = date_time_ymd(2024, 1, 1);
    params.not_after = date_time_ymd(2036, 1, 1);
    params
}

/// Rebuilds a fixture root CA from its common name and PEM private key.
pub fn load_ca(cn: &str, key_pem: &str) -> (Certificate, KeyPair) {
    let key = KeyPair::from_pem(key_pem).unwrap();
    let cert = ca_params(cn, None).self_signed(&key).unwrap();
    (cert, key)
}

/// A CRL issued by `issuer` that revokes `revoked` serials.
pub fn crl(
    issuer: &Certificate,
    issuer_key: &KeyPair,
    number: u64,
    this_update: OffsetDateTime,
    next_update: OffsetDateTime,
    revoked: &[u64],
) -> rcgen::CertificateRevocationList {
    CertificateRevocationListParams {
        this_update,
        next_update,
        crl_number: SerialNumber::from(number),
        issuing_distribution_point: None,
        revoked_certs: revoked
            .iter()
            .map(|serial| RevokedCertParams {
                serial_number: SerialNumber::from(*serial),
                revocation_time: this_update,
                reason_code: Some(RevocationReason::KeyCompromise),
                invalidity_date: None,
            })
            .collect(),
        key_identifier_method: KeyIdMethod::Sha256,
    }
    .signed_by(issuer, issuer_key)
    .unwrap()
}

/// PEM-armours arbitrary DER, so tests can feed hand-modified DER through the
/// PEM-only public API.
pub fn pem(label: &str, der: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut b64 = String::new();
    for chunk in der.chunks(3) {
        let n = chunk.len();
        let v = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= n {
                b64.push(ALPHABET[((v >> (18 - 6 * i)) & 0x3f) as usize] as char);
            } else {
                b64.push('=');
            }
        }
    }
    let mut out = format!("-----BEGIN {label}-----\n");
    for line in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).unwrap());
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}
