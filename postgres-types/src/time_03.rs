use bytes::BytesMut;
use postgres_protocol::types;
use std::convert::TryFrom;
use std::error::Error;
use time_03::{Date, Duration, OffsetDateTime, PrimitiveDateTime, Time};

use crate::{FromSql, IsNull, ToSql, Type};

fn base() -> PrimitiveDateTime {
    PrimitiveDateTime::new(Date::from_ordinal_date(2000, 1).unwrap(), Time::MIDNIGHT)
}

impl<'a> FromSql<'a> for PrimitiveDateTime {
    fn from_sql(_: &Type, raw: &[u8]) -> Result<PrimitiveDateTime, Box<dyn Error + Sync + Send>> {
        let t = types::timestamp_from_sql(raw)?;
        Ok(base()
            .checked_add(Duration::microseconds(t))
            .ok_or("value too large to decode")?)
    }

    accepts!(TIMESTAMP);
}

impl ToSql for PrimitiveDateTime {
    fn to_sql(&self, _: &Type, w: &mut BytesMut) -> Result<IsNull, Box<dyn Error + Sync + Send>> {
        let time = match i64::try_from((*self - base()).whole_microseconds()) {
            Ok(time) => time,
            Err(_) => return Err("value too large to transmit".into()),
        };
        types::timestamp_to_sql(time, w);
        Ok(IsNull::No)
    }

    accepts!(TIMESTAMP);
    to_sql_checked!();
}

impl<'a> FromSql<'a> for OffsetDateTime {
    fn from_sql(type_: &Type, raw: &[u8]) -> Result<OffsetDateTime, Box<dyn Error + Sync + Send>> {
        let primitive = PrimitiveDateTime::from_sql(type_, raw)?;
        Ok(primitive.assume_utc())
    }

    accepts!(TIMESTAMPTZ);
}

impl ToSql for OffsetDateTime {
    fn to_sql(&self, _: &Type, w: &mut BytesMut) -> Result<IsNull, Box<dyn Error + Sync + Send>> {
        // Subtract directly rather than converting to UTC first: `to_offset`
        // panics when the UTC date-time falls outside `time`'s year range,
        // which a value near the range edge with a non-UTC offset can reach.
        let time = match i64::try_from((*self - base().assume_utc()).whole_microseconds()) {
            Ok(time) => time,
            Err(_) => return Err("value too large to transmit".into()),
        };
        types::timestamp_to_sql(time, w);
        Ok(IsNull::No)
    }

    accepts!(TIMESTAMPTZ);
    to_sql_checked!();
}

impl<'a> FromSql<'a> for Date {
    fn from_sql(_: &Type, raw: &[u8]) -> Result<Date, Box<dyn Error + Sync + Send>> {
        let jd = types::date_from_sql(raw)?;
        Ok(base()
            .date()
            .checked_add(Duration::days(i64::from(jd)))
            .ok_or("value too large to decode")?)
    }

    accepts!(DATE);
}

impl ToSql for Date {
    fn to_sql(&self, _: &Type, w: &mut BytesMut) -> Result<IsNull, Box<dyn Error + Sync + Send>> {
        let jd = (*self - base().date()).whole_days();
        if jd > i64::from(i32::max_value()) || jd < i64::from(i32::min_value()) {
            return Err("value too large to transmit".into());
        }

        types::date_to_sql(jd as i32, w);
        Ok(IsNull::No)
    }

    accepts!(DATE);
    to_sql_checked!();
}

impl<'a> FromSql<'a> for Time {
    fn from_sql(_: &Type, raw: &[u8]) -> Result<Time, Box<dyn Error + Sync + Send>> {
        let usec = types::time_from_sql(raw)?;
        Ok(Time::MIDNIGHT + Duration::microseconds(usec))
    }

    accepts!(TIME);
}

impl ToSql for Time {
    fn to_sql(&self, _: &Type, w: &mut BytesMut) -> Result<IsNull, Box<dyn Error + Sync + Send>> {
        let delta = *self - Time::MIDNIGHT;
        let time = match i64::try_from(delta.whole_microseconds()) {
            Ok(time) => time,
            Err(_) => return Err("value too large to transmit".into()),
        };
        types::time_to_sql(time, w);
        Ok(IsNull::No)
    }

    accepts!(TIME);
    to_sql_checked!();
}

#[cfg(test)]
mod test {
    use super::*;
    use time_03::{Month, UtcOffset};

    fn encode<T: ToSql>(value: &T, ty: &Type) -> Result<i64, Box<dyn Error + Sync + Send>> {
        let mut buf = BytesMut::new();
        value.to_sql(ty, &mut buf)?;
        Ok(types::timestamp_from_sql(&buf)?)
    }

    #[test]
    fn timestamp_out_of_range_errors() {
        // `infinity` / `-infinity` and other values outside `time`'s year
        // range must error rather than panic.
        for raw in [
            i64::MAX,
            i64::MIN,
            300_000_000_000_000_000,
            -300_000_000_000_000_000,
        ] {
            let raw = raw.to_be_bytes();
            assert!(<PrimitiveDateTime as FromSql>::from_sql(&Type::TIMESTAMP, &raw).is_err());
            assert!(<OffsetDateTime as FromSql>::from_sql(&Type::TIMESTAMPTZ, &raw).is_err());
        }
    }

    #[test]
    fn timestamp_in_range_decodes() {
        let raw = 0i64.to_be_bytes();
        assert_eq!(
            <PrimitiveDateTime as FromSql>::from_sql(&Type::TIMESTAMP, &raw).unwrap(),
            base()
        );
    }

    #[test]
    fn date_out_of_range_errors() {
        for raw in [i32::MAX, i32::MIN, 10_000_000, -10_000_000] {
            let raw = raw.to_be_bytes();
            assert!(<Date as FromSql>::from_sql(&Type::DATE, &raw).is_err());
        }
    }

    #[test]
    fn date_in_range_decodes() {
        let raw = 1_000i32.to_be_bytes();
        assert_eq!(
            <Date as FromSql>::from_sql(&Type::DATE, &raw).unwrap(),
            base().date() + Duration::days(1_000)
        );
    }

    #[test]
    fn offset_date_time_near_range_edge_encodes() {
        // The UTC equivalent of these values lies outside `time`'s year range,
        // but the value itself is valid and fits a PostgreSQL timestamptz.
        let max = PrimitiveDateTime::new(
            Date::from_calendar_date(9999, Month::December, 31).unwrap(),
            Time::from_hms(23, 0, 0).unwrap(),
        );
        let late = max.assume_offset(UtcOffset::from_hms(-5, 0, 0).unwrap());
        let expected = (max - base()).whole_microseconds() as i64 + 5 * 3_600_000_000;
        assert_eq!(encode(&late, &Type::TIMESTAMPTZ).unwrap(), expected);

        let min = PrimitiveDateTime::new(
            Date::from_calendar_date(-9999, Month::January, 1).unwrap(),
            Time::MIDNIGHT,
        );
        let early = min.assume_offset(UtcOffset::from_hms(5, 0, 0).unwrap());
        let expected = (min - base()).whole_microseconds() as i64 - 5 * 3_600_000_000;
        assert_eq!(encode(&early, &Type::TIMESTAMPTZ).unwrap(), expected);
    }

    #[test]
    fn offset_date_time_encodes_in_utc() {
        let utc = base().assume_utc();
        let shifted = utc.to_offset(UtcOffset::from_hms(3, 30, 0).unwrap());
        assert_eq!(encode(&utc, &Type::TIMESTAMPTZ).unwrap(), 0);
        assert_eq!(encode(&shifted, &Type::TIMESTAMPTZ).unwrap(), 0);
    }
}
