//! Generates the throwaway PKI used by the TLS qualification rig.
//!
//! Every key is generated fresh on each run and lives only in the rig's
//! fixture directory; nothing here is a real credential.

use rcgen::{
    date_time_ymd, Certificate, CertificateParams, ExtendedKeyUsagePurpose, KeyPair,
    KeyUsagePurpose, SanType, SerialNumber,
};
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use time::OffsetDateTime;
use tls_qualification::{ca_params, crl, name, CA_A_CN};

struct Ca {
    cert: Certificate,
    key: KeyPair,
}

fn ca(cn: &str) -> Ca {
    let key = KeyPair::generate().unwrap();
    let cert = ca_params(cn, None).self_signed(&key).unwrap();
    Ca { cert, key }
}

fn intermediate(issuer: &Ca, cn: &str, serial: u64) -> Ca {
    let key = KeyPair::generate().unwrap();
    let cert = ca_params(cn, Some(serial))
        .signed_by(&key, &issuer.cert, &issuer.key)
        .unwrap();
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

    let ca_a = ca(CA_A_CN);
    let ca_a2 = ca("qualification CA A2 (rotated)");
    let ca_b = ca("qualification CA B (untrusted)");
    write(&dir, "ca-a.crt", &ca_a.cert.pem());
    // Lets tests sign short-lived CRLs at test time (see `tls_qualification::load_ca`).
    write(&dir, "ca-a.key", &ca_a.key.serialize_pem());
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

    let (this_update, next_update) = (date_time_ymd(2025, 1, 1), date_time_ymd(2035, 1, 1));
    let crl_pem = |issuer: &Ca, number: u64, next_update: OffsetDateTime, revoked: &[u64]| {
        // thisUpdate must precede nextUpdate; the stale CRL is issued earlier.
        let this_update = if next_update > this_update { this_update } else { date_time_ymd(2024, 1, 1) };
        crl(&issuer.cert, &issuer.key, number, this_update, next_update, revoked)
            .pem()
            .unwrap()
    };
    write(&dir, "crl-a-revokes-server-valid.pem", &crl_pem(&ca_a, 1, next_update, &[1001]));
    write(&dir, "crl-a-empty.pem", &crl_pem(&ca_a, 2, next_update, &[]));
    // Past its nextUpdate, revoking nothing.
    write(&dir, "crl-a-expired.pem", &crl_pem(&ca_a, 3, date_time_ymd(2024, 6, 1), &[]));
    // nextUpdate from 2050 on is encoded as GeneralizedTime rather than UTCTime.
    write(&dir, "crl-a-empty-2051.pem", &crl_pem(&ca_a, 4, date_time_ymd(2051, 3, 1), &[]));

    // A three-level chain: root CA C -> intermediate CA C1 (serial 6001) ->
    // server leaf. The server presents the leaf and the intermediate.
    let ca_c = ca("qualification CA C");
    let int_c1 = intermediate(&ca_c, "qualification intermediate CA C1", 6001);
    write(&dir, "ca-c.crt", &ca_c.cert.pem());
    let chained = leaf(&int_c1, "pg.test", &pg_sans, 5001, false, current);
    write(
        &dir,
        "server-chained.crt",
        &format!("{}{}", chained.0.pem(), int_c1.cert.pem()),
    );
    write(&dir, "server-chained.key", &chained.1.serialize_pem());
    write(&dir, "crl-c-revokes-int-c1.pem", &crl_pem(&ca_c, 1, next_update, &[6001]));
    write(&dir, "crl-c-empty.pem", &crl_pem(&ca_c, 2, next_update, &[]));
    write(&dir, "crl-c1-empty.pem", &crl_pem(&int_c1, 1, next_update, &[]));

    println!("fixtures written to {}", dir.display());
}
