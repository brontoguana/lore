use crate::error::{LoreError, Result};
use crate::model::OrderKey;

const SEGMENT_WIDTH: usize = 8;
const MID_SEGMENT: u32 = 0x8000_0000;

fn parse_segments(key: &OrderKey) -> Result<Vec<u32>> {
    key.as_str()
        .split('.')
        .map(|segment| {
            u32::from_str_radix(segment, 16)
                .map_err(|_| LoreError::Validation(format!("invalid order key segment: {segment}")))
        })
        .collect()
}

fn encode_segments(segments: &[u32]) -> Result<OrderKey> {
    let value = segments
        .iter()
        .map(|segment| format!("{segment:0SEGMENT_WIDTH$X}"))
        .collect::<Vec<_>>()
        .join(".");
    OrderKey::new(value)
}

fn compare_segments(left: &[u32], right: &[u32]) -> std::cmp::Ordering {
    left.cmp(right)
}

fn after_segments(left: Option<&[u32]>) -> Vec<u32> {
    match left {
        Some([head, tail @ ..]) => {
            let mut result = vec![*head];
            result.extend(after_segments(Some(tail)));
            result
        }
        _ => vec![MID_SEGMENT],
    }
}

fn between_segments(left: Option<&[u32]>, right: Option<&[u32]>) -> Result<Vec<u32>> {
    match (left, right) {
        (None, None) => Ok(vec![MID_SEGMENT]),
        (Some(left), Some(right)) if compare_segments(left, right) != std::cmp::Ordering::Less => {
            Err(LoreError::InvalidOrderRange)
        }
        (Some([l_head, l_tail @ ..]), Some([r_head, r_tail @ ..])) if l_head == r_head => {
            let mut prefix = vec![*l_head];
            prefix.extend(between_segments(Some(l_tail), Some(r_tail))?);
            Ok(prefix)
        }
        (Some([l_head, l_tail @ ..]), Some([r_head, ..])) => {
            if r_head - l_head > 1 {
                Ok(vec![*l_head + ((r_head - l_head) / 2)])
            } else {
                let mut prefix = vec![*l_head];
                prefix.extend(after_segments(Some(l_tail)));
                Ok(prefix)
            }
        }
        (Some([l_head, l_tail @ ..]), None) => {
            let mut prefix = vec![*l_head];
            prefix.extend(after_segments(Some(l_tail)));
            Ok(prefix)
        }
        (None, Some([r_head, ..])) if *r_head > 1 => Ok(vec![r_head / 2]),
        (None, Some(_)) => Ok(vec![0, MID_SEGMENT]),
        (Some([]), right) => between_segments(None, right),
        (left, Some([])) => between_segments(left, None),
    }
}

pub fn generate_order_key(left: Option<&OrderKey>, right: Option<&OrderKey>) -> Result<OrderKey> {
    let left_segments = left.map(parse_segments).transpose()?;
    let right_segments = right.map(parse_segments).transpose()?;
    let key = between_segments(left_segments.as_deref(), right_segments.as_deref())?;
    encode_segments(&key)
}

#[cfg(test)]
mod tests {
    use super::generate_order_key;
    use crate::model::OrderKey;

    #[test]
    fn generates_middle_key_for_empty_stream() {
        let key = generate_order_key(None, None).unwrap();
        assert_eq!(key.as_str(), "80000000");
    }

    #[test]
    fn inserts_between_existing_keys() {
        let left = OrderKey::new("40000000".into()).unwrap();
        let right = OrderKey::new("C0000000".into()).unwrap();
        let middle = generate_order_key(Some(&left), Some(&right)).unwrap();

        assert!(left < middle);
        assert!(middle < right);
    }

    #[test]
    fn inserts_after_adjacent_prefix_using_deeper_segment() {
        let left = OrderKey::new("00000001".into()).unwrap();
        let right = OrderKey::new("00000002".into()).unwrap();
        let middle = generate_order_key(Some(&left), Some(&right)).unwrap();

        assert_eq!(middle.as_str(), "00000001.80000000");
        assert!(left < middle);
        assert!(middle < right);
    }

    #[test]
    fn supports_repeated_inserts_without_renumbering() {
        let mut left = OrderKey::new("00000001".into()).unwrap();
        let right = OrderKey::new("00000002".into()).unwrap();

        for _ in 0..32 {
            let next = generate_order_key(Some(&left), Some(&right)).unwrap();
            assert!(left < next);
            assert!(next < right);
            left = next;
        }
    }
}
