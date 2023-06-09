/// Serialization and deserialization of `chrono::DateTime` as a numeric date.
///
/// The serialization format is a JSON numeric value representing the number of
/// seconds from 1970-01-01T00:00:00Z UTC until the specified UTC date/time,
/// ignoring leap seconds.
use chrono::{DateTime, TimeZone, Utc};
use serde::{de, de::Deserialize, Deserializer, Serializer};

pub fn serialize<S>(date: &Option<DateTime<Utc>>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match date {
        Some(dt) => serializer.serialize_some(&dt.timestamp()),
        None => serializer.serialize_none(),
    }
}

pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<DateTime<Utc>>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt = Option::<i64>::deserialize(deserializer)?;

    match opt {
        Some(timestamp) => Ok(Some(
            Utc.timestamp_opt(timestamp, 0)
                .earliest()
                .ok_or_else(|| de::Error::custom(format!("invalid timestamp: {timestamp:?}")))?,
        )),
        None => Ok(None),
    }
}
