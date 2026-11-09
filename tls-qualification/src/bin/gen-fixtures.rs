//! Generates the throwaway PKI used by the TLS qualification rig.
//!
//! Every key is generated fresh on each run and lives only in the rig's
//! fixture directory; nothing here is a real credential.

use rcgen::{
    date_time_ymd, BasicConstraints, Certificate, CertificateParams,
    CertificateRevocationListParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyIdMethod, KeyPair, KeyUsagePurpose, RevocationReason, RevokedCertParams, SanType,
    SerialNumber,
};
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use time::OffsetDateTime;

struct Ca {
    cert: Certificate,
    key: KeyPair,
}

fn name(cn: &str) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::OrganizationName, "AST-2128 qualification");
    dn.push(DnType::CommonName, cn);
    dn
}

fn ca(cn: &str) -> Ca {
    let mut params = CertificateParams::default();
    params.distinguished_name = name(cn);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    params.not_before = date_time_ymd(2024, 1, 1);
    params.not_after = date_time_ymd(2036, 1, 1);
    let key = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    Ca { cert, key }
}

enum San<'a> {
    Dns(&'a str),
    Ip(&'a str),
}

fn leaf(
    issuer: &Ca,
    cn: &str,
    sans: &[San<'_>],
    serial: u64,
    client: bool,
    validity: (OffsetDateTime, OffsetDateTime),
) -> (Certificate, KeyPair) {
    let mut params = CertificateParams::default();
    params.distinguished_name = name(cn);
    params.subject_alt_names = sans
        .iter()
        .map(|san| match san {
            San::Dns(dns) => SanType::DnsName((*dns).try_into().unwrap()),
            San::Ip(ip) => SanType::IpAddress(ip.parse::<IpAddr>().unwrap()),
        })
        .collect();
    params.serial_number = Some(SerialNumber::from(serial));
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![if client {
        ExtendedKeyUsagePurpose::ClientAuth
    } else {
        ExtendedKeyUsagePurpose::ServerAuth
    }];
    params.not_before = validity.0;
    params.not_after = validity.1;
    let key = KeyPair::generate().unwrap();
    let cert = params.signed_by(&key, &issuer.cert, &issuer.key).unwrap();
    (cert, key)
}

fn write(dir: &Path, name: &str, contents: &str) {
    fs::write(dir.join(name), contents).unwrap();
}

fn write_pair(dir: &Path, name: &str, pair: &(Certificate, KeyPair)) {
    write(dir, &format!("{name}.crt"), &pair.0.pem());
    write(dir, &format!("{name}.key"), &pair.1.serialize_pem());
}

fn main() {
    let dir = PathBuf::from(std::env::args().nth(1).expect("usage: gen-fixtures <dir>"));
    fs::create_dir_all(&dir).unwrap();

    let current = (date_time_ymd(2025, 1, 1), date_time_ymd(2035, 1, 1));
    let expired = (date_time_ymd(2020, 1, 1), date_time_ymd(2021, 1, 1));

    let ca_a = ca("qualification CA A");
    let ca_a2 = ca("qualification CA A2 (rotated)");
    let ca_b = ca("qualification CA B (untrusted)");
    write(&dir, "ca-a.crt", &ca_a.cert.pem());
    write(&dir, "ca-a2.crt", &ca_a2.cert.pem());
    write(&dir, "ca-b.crt", &ca_b.cert.pem());
    write(
        &dir,
        "ca-a-and-a2.crt",
        &format!("{}{}", ca_a.cert.pem(), ca_a2.cert.pem()),
    );

    let pg_sans = [San::Dns("localhost"), San::Dns("pg.test"), San::Ip("127.0.0.1")];
    write_pair(&dir, "server-valid", &leaf(&ca_a, "pg.test", &pg_sans, 1001, false, current));
    write_pair(&dir, "server-expired", &leaf(&ca_a, "pg.test", &pg_sans, 1002, false, expired));
    write_pair(&dir, "server-rotated", &leaf(&ca_a2, "pg.test", &pg_sans, 2001, false, current));

    // YugabyteDB realm A advertises 127.0.0.2 and has an IP SAN for it.
    write_pair(
        &dir,
        "yb-a",
        &leaf(&ca_a, "yb-a.test", &[San::Dns("yb-a.test"), San::Ip("127.0.0.2")], 3001, false, current),
    );
    // Realm B advertises 127.0.0.3 but its certificate only names yb-b.test.
    write_pair(
        &dir,
        "yb-b",
        &leaf(&ca_a, "yb-b.test", &[San::Dns("yb-b.test")], 3002, false, current),
    );

    write_pair(&dir, "client-postgres", &leaf(&ca_a, "postgres", &[], 4001, true, current));
    write_pair(&dir, "client-wrong-ca", &leaf(&ca_b, "postgres", &[], 4002, true, current));
    write_pair(&dir, "client-expired", &leaf(&ca_a, "postgres", &[], 4003, true, expired));
    // A key that matches no certificate.
    write(&dir, "unrelated.key", &KeyPair::generate().unwrap().serialize_pem());

    let crl = CertificateRevocationListParams {
        this_update: date_time_ymd(2025, 1, 1),
        next_update: date_time_ymd(2035, 1, 1),
        crl_number: SerialNumber::from(1u64),
        issuing_distribution_point: None,
        revoked_certs: vec![RevokedCertParams {
            serial_number: SerialNumber::from(1001u64),
            revocation_time: date_time_ymd(2025, 6, 1),
            reason_code: Some(RevocationReason::KeyCompromise),
            invalidity_date: None,
        }],
        key_identifier_method: KeyIdMethod::Sha256,
    }
    .signed_by(&ca_a.cert, &ca_a.key)
    .unwrap();
    write(&dir, "crl-a-revokes-server-valid.pem", &crl.pem().unwrap());
    let empty_crl = CertificateRevocationListParams {
        this_update: date_time_ymd(2025, 1, 1),
        next_update: date_time_ymd(2035, 1, 1),
        crl_number: SerialNumber::from(2u64),
        issuing_distribution_point: None,
        revoked_certs: vec![],
        key_identifier_method: KeyIdMethod::Sha256,
    }
    .signed_by(&ca_a.cert, &ca_a.key)
    .unwrap();
    write(&dir, "crl-a-empty.pem", &empty_crl.pem().unwrap());

    println!("fixtures written to {}", dir.display());
}
