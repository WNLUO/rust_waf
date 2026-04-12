use super::*;

pub(super) fn pick_timestamp(
    object: &serde_json::Map<String, Value>,
    keys: &[&str],
) -> Option<i64> {
    for key in keys {
        let Some(value) = object.get(*key) else {
            continue;
        };

        match value {
            Value::Number(number) => {
                if let Some(parsed) = number.as_i64() {
                    return Some(normalize_timestamp(parsed));
                }
            }
            Value::String(inner) => {
                let trimmed = inner.trim();
                if trimmed.is_empty() {
                    continue;
                }
                if let Ok(parsed) = trimmed.parse::<i64>() {
                    return Some(normalize_timestamp(parsed));
                }
                if let Some(parsed) = parse_rfc3339_timestamp(trimmed) {
                    return Some(parsed);
                }
            }
            _ => {}
        }
    }

    None
}

pub(super) fn normalize_timestamp(value: i64) -> i64 {
    if value > 10_000_000_000 {
        value / 1000
    } else {
        value
    }
}

pub(super) fn parse_rfc3339_timestamp(value: &str) -> Option<i64> {
    let (date_part, rest) = value.split_once('T')?;
    let (year, month, day) = parse_date(date_part)?;
    let (time_part, offset_seconds) = parse_time_and_offset(rest)?;
    let (hour, minute, second) = parse_time(time_part)?;
    let days = days_from_civil(year, month, day);
    Some(days * 86_400 + hour as i64 * 3_600 + minute as i64 * 60 + second as i64 - offset_seconds)
}

fn parse_date(value: &str) -> Option<(i32, u32, u32)> {
    let mut parts = value.split('-');
    let year = parts.next()?.parse::<i32>().ok()?;
    let month = parts.next()?.parse::<u32>().ok()?;
    let day = parts.next()?.parse::<u32>().ok()?;
    if parts.next().is_some() || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    Some((year, month, day))
}

fn parse_time_and_offset(value: &str) -> Option<(&str, i64)> {
    if let Some(time_part) = value.strip_suffix('Z') {
        return Some((time_part, 0));
    }

    let tz_index = value
        .char_indices()
        .skip(8)
        .find_map(|(index, ch)| matches!(ch, '+' | '-').then_some(index))?;
    let (time_part, offset_part) = value.split_at(tz_index);
    let sign = if offset_part.starts_with('-') { -1 } else { 1 };
    let offset = &offset_part[1..];
    let (hours, minutes) = offset.split_once(':')?;
    let hours = hours.parse::<i64>().ok()?;
    let minutes = minutes.parse::<i64>().ok()?;
    Some((time_part, sign * (hours * 3_600 + minutes * 60)))
}

fn parse_time(value: &str) -> Option<(u32, u32, u32)> {
    let mut parts = value.split(':');
    let hour = parts.next()?.parse::<u32>().ok()?;
    let minute = parts.next()?.parse::<u32>().ok()?;
    let second_part = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    let second = second_part
        .split_once('.')
        .map(|(whole, _)| whole)
        .unwrap_or(second_part)
        .parse::<u32>()
        .ok()?;
    if hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    Some((hour, minute, second))
}

fn days_from_civil(year: i32, month: u32, day: u32) -> i64 {
    let year = year - i32::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month = month as i32;
    let day = day as i32;
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    (era * 146_097 + day_of_era - 719_468) as i64
}

pub(super) fn unix_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
