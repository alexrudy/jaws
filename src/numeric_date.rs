/// Serialization and deserialization of `chrono::DateTime` as a numeric date.
use chrono::{DateTime, TimeZone, Utc};
use serde::{de, de::Deserialize, Deserializer, Serializer};

pub fn serialize<S>(date: &DateTime<Utc>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_i64(date.timestamp())
}

pub fn deserialize<'de, D>(deserializer: D) -> Result<DateTime<Utc>, D::Error>
where
    D: Deserializer<'de>,
{
    let timestamp = i64::deserialize(deserializer)?;
    Utc.timestamp_opt(timestamp, 0)
        .earliest()
        .ok_or_else(|| de::Error::custom(format!("invalid timestamp: {timestamp:?}")))
}
