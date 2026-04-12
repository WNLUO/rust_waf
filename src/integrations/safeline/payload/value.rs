use super::*;

pub(super) fn pick_string(
    object: &serde_json::Map<String, Value>,
    keys: &[&str],
) -> Option<String> {
    for key in keys {
        let Some(value) = object.get(*key) else {
            continue;
        };

        match value {
            Value::String(inner) if !inner.trim().is_empty() => {
                return Some(inner.trim().to_string());
            }
            Value::Number(number) => return Some(number.to_string()),
            Value::Bool(flag) => return Some(flag.to_string()),
            _ => {}
        }
    }

    None
}

pub(super) fn pick_first_array_string(
    object: &serde_json::Map<String, Value>,
    keys: &[&str],
) -> Option<String> {
    pick_array_strings(object, keys)?.into_iter().next()
}

pub(super) fn pick_array_strings(
    object: &serde_json::Map<String, Value>,
    keys: &[&str],
) -> Option<Vec<String>> {
    for key in keys {
        let Some(value) = object.get(*key) else {
            continue;
        };

        if let Some(array) = value.as_array() {
            let mut values = Vec::new();
            for item in array {
                if let Some(inner) = item.as_str() {
                    let trimmed = inner.trim();
                    if !trimmed.is_empty() {
                        values.push(trimmed.to_string());
                    }
                }
            }
            if !values.is_empty() {
                return Some(values);
            }
        }
    }

    None
}

pub(super) fn pick_i64(object: &serde_json::Map<String, Value>, keys: &[&str]) -> Option<i64> {
    for key in keys {
        let Some(value) = object.get(*key) else {
            continue;
        };

        match value {
            Value::Number(number) => return number.as_i64(),
            Value::String(inner) => {
                if let Ok(parsed) = inner.trim().parse::<i64>() {
                    return Some(parsed);
                }
            }
            _ => {}
        }
    }

    None
}

pub(super) fn pick_bool(object: &serde_json::Map<String, Value>, keys: &[&str]) -> Option<bool> {
    for key in keys {
        let Some(value) = object.get(*key) else {
            continue;
        };

        match value {
            Value::Bool(flag) => return Some(*flag),
            Value::Number(number) => {
                if let Some(parsed) = number.as_i64() {
                    return Some(parsed != 0);
                }
            }
            Value::String(inner) => {
                let normalized = inner.trim().to_ascii_lowercase();
                match normalized.as_str() {
                    "true" | "1" | "yes" | "on" | "enabled" => return Some(true),
                    "false" | "0" | "no" | "off" | "disabled" => return Some(false),
                    _ => {}
                }
            }
            _ => {}
        }
    }

    None
}
