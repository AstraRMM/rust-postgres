//! Minimal, bounds-checked DER reading for the two certificate facts the
//! adapter needs outside rustls: the signature algorithm (for RFC 5929
//! `tls-server-end-point` channel binding) and the validity window (to reject
//! credential material that is already outside its validity period when it is
//! loaded). Chain and identity verification is never done here; that is
//! rustls-webpki's job.

use sha2::{Digest, Sha256, Sha384, Sha512};

const SEQUENCE: u8 = 0x30;
const OID: u8 = 0x06;
const INTEGER: u8 = 0x02;
const UTC_TIME: u8 = 0x17;
const GENERALIZED_TIME: u8 = 0x18;
const VERSION: u8 = 0xa0;

fn read_tlv(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = input.split_first()?;
    if tag & 0x1f == 0x1f {
        return None;
    }
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (first as usize, rest)
    } else {
        let count = (first & 0x7f) as usize;
        if count == 0 || count > 4 || rest.len() < count {
            return None;
        }
        let mut len = 0usize;
        for &b in &rest[..count] {
            len = (len << 8) | b as usize;
        }
        (len, &rest[count..])
    };
    if rest.len() < len {
        return None;
    }
    Some((tag, &rest[..len], &rest[len..]))
}

fn expect(input: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
    let (found, value, rest) = read_tlv(input)?;
    if found == tag {
        Some((value, rest))
    } else {
        None
    }
}

fn tbs_and_signature_algorithm(cert: &[u8]) -> Option<(&[u8], &[u8])> {
    let (cert, _) = expect(cert, SEQUENCE)?;
    let (tbs, rest) = expect(cert, SEQUENCE)?;
    let (algorithm, _) = expect(rest, SEQUENCE)?;
    let (oid, _) = expect(algorithm, OID)?;
    Some((tbs, oid))
}

/// Returns `(not_before, not_after)` as Unix seconds.
pub(crate) fn validity(cert: &[u8]) -> Option<(i64, i64)> {
    let (tbs, _) = tbs_and_signature_algorithm(cert)?;
    let mut rest = tbs;
    let (tag, _, after) = read_tlv(rest)?;
    if tag == VERSION {
        rest = after;
    }
    let (_, rest) = expect(rest, INTEGER)?; // serialNumber
    let (_, rest) = expect(rest, SEQUENCE)?; // signature
    let (_, rest) = expect(rest, SEQUENCE)?; // issuer
    let (validity, _) = expect(rest, SEQUENCE)?;
    let (tag, not_before, rest) = read_tlv(validity)?;
    let not_before = parse_time(tag, not_before)?;
    let (tag, not_after, _) = read_tlv(rest)?;
    let not_after = parse_time(tag, not_after)?;
    Some((not_before, not_after))
}

fn digits(input: &[u8]) -> Option<i64> {
    let mut value = 0i64;
    for &b in input {
        if !b.is_ascii_digit() {
            return None;
        }
        value = value * 10 + i64::from(b - b'0');
    }
    Some(value)
}

fn parse_time(tag: u8, value: &[u8]) -> Option<i64> {
    let (year, rest) = match (tag, value.len()) {
        (UTC_TIME, 13) => {
            let yy = digits(&value[..2])?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, &value[2..])
        }
        (GENERALIZED_TIME, 15) => (digits(&value[..4])?, &value[4..]),
        _ => return None,
    };
    if rest[10] != b'Z' {
        return None;
    }
    let month = digits(&rest[0..2])?;
    let day = digits(&rest[2..4])?;
    let hour = digits(&rest[4..6])?;
    let minute = digits(&rest[6..8])?;
    let second = digits(&rest[8..10])?;
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    Some(days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second)
}

// Howard Hinnant's days_from_civil.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

const RSA_PREFIX: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01];
const ECDSA_SHA1: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x01];
const ECDSA_SHA2_PREFIX: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03];

enum EndPointHash {
    Sha256,
    Sha384,
    Sha512,
}

/// Computes RFC 5929 `tls-server-end-point` channel-binding data for the
/// server leaf certificate: MD5/SHA-1 signatures hash with SHA-256, otherwise
/// the signature's own hash. Algorithms without a single defined hash
/// (Ed25519, RSA-PSS) return `None`, in which case SCRAM proceeds without
/// channel binding unless `channel_binding=require` was set.
pub(crate) fn tls_server_end_point(cert: &[u8]) -> Option<Vec<u8>> {
    let (_, oid) = tbs_and_signature_algorithm(cert)?;
    let hash = if oid.len() == RSA_PREFIX.len() + 1 && oid.starts_with(RSA_PREFIX) {
        match oid[RSA_PREFIX.len()] {
            0x04 | 0x05 | 0x0b => EndPointHash::Sha256,
            0x0c => EndPointHash::Sha384,
            0x0d => EndPointHash::Sha512,
            _ => return None,
        }
    } else if oid == ECDSA_SHA1 {
        EndPointHash::Sha256
    } else if oid.len() == ECDSA_SHA2_PREFIX.len() + 1 && oid.starts_with(ECDSA_SHA2_PREFIX) {
        match oid[ECDSA_SHA2_PREFIX.len()] {
            0x02 => EndPointHash::Sha256,
            0x03 => EndPointHash::Sha384,
            0x04 => EndPointHash::Sha512,
            _ => return None,
        }
    } else {
        return None;
    };
    Some(match hash {
        EndPointHash::Sha256 => Sha256::digest(cert).to_vec(),
        EndPointHash::Sha384 => Sha384::digest(cert).to_vec(),
        EndPointHash::Sha512 => Sha512::digest(cert).to_vec(),
    })
}
