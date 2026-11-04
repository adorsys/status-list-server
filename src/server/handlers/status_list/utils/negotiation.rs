use axum::http::{HeaderMap, header};

use super::constants::{ACCEPT_STATUS_LISTS_HEADER_CWT, ACCEPT_STATUS_LISTS_HEADER_JWT};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AcceptType {
    Jwt,
    Cwt,
}

impl AcceptType {
    /// Tie-break order: earlier wins.
    pub(crate) const ALL: [Self; 2] = [Self::Jwt, Self::Cwt];

    pub(crate) fn media_type(self) -> &'static str {
        match self {
            Self::Jwt => ACCEPT_STATUS_LISTS_HEADER_JWT,
            Self::Cwt => ACCEPT_STATUS_LISTS_HEADER_CWT,
        }
    }

    /// Exact beats `application/*`, which beats `*/*` (RFC 9110 §12.5.1).
    fn precedence(self, range: &str) -> Option<u8> {
        if range.eq_ignore_ascii_case(self.media_type()) {
            Some(2)
        } else if range.eq_ignore_ascii_case("application/*") {
            Some(1)
        } else if range == "*/*" {
            Some(0)
        } else {
            None
        }
    }
}

/// Ignores parameters other than q, a deliberate RFC 9110 deviation; no served type has any.
/// JWT wins ties and wildcards; None means 406.
pub(crate) fn negotiate_accept<'a>(
    fields: impl IntoIterator<Item = &'a str>,
) -> Option<AcceptType> {
    let mut ranges = fields
        .into_iter()
        .flat_map(|f| split_top_level(f, ','))
        .map(str::trim)
        .filter(|r| !r.is_empty())
        .peekable();
    if ranges.peek().is_none() {
        return Some(AcceptType::Jwt);
    }

    // Most specific range wins, so `*/*` can't override an explicit q=0.
    let mut best: [Option<(u8, f32)>; 2] = [None; 2];
    for range in ranges {
        // Quoted parameter values may contain ';', so split at the top level only.
        let (media, params) = match find_top_level(range, ';') {
            Some(i) => (range[..i].trim(), &range[i + 1..]),
            None => (range.trim(), ""),
        };
        let q = weight(params);
        for (slot, ty) in best.iter_mut().zip(AcceptType::ALL) {
            let Some(p) = ty.precedence(media.trim()) else {
                continue;
            };
            *slot = match *slot {
                Some((cur_p, _)) if cur_p > p => *slot,
                Some((cur_p, cur_q)) if cur_p == p => Some((p, cur_q.max(q))),
                _ => Some((p, q)),
            };
        }
    }

    let q = |i: usize| best[i].map_or(0.0, |(_, q)| q);
    match (q(0), q(1)) {
        (jwt, cwt) if cwt > jwt => Some(AcceptType::Cwt),
        (jwt, _) if jwt > 0.0 => Some(AcceptType::Jwt),
        _ => None,
    }
}

pub(crate) fn client_accepts_gzip(headers: &HeaderMap) -> bool {
    let mut entries: Vec<(&str, f32)> = Vec::new();
    for val in headers.get_all(header::ACCEPT_ENCODING) {
        let Ok(val) = val.to_str() else { continue };
        for s in split_top_level(val, ',') {
            let s = s.trim();
            if s.is_empty() {
                continue;
            }
            let (coding, params) = match find_top_level(s, ';') {
                Some(i) => (s[..i].trim(), &s[i + 1..]),
                None => (s.trim(), ""),
            };
            entries.push((coding, weight(params)));
        }
    }

    match entries
        .iter()
        .find(|(c, _)| c.eq_ignore_ascii_case("gzip"))
        .map(|(_, q)| *q)
    {
        Some(q) => q > 0.0,
        None => entries
            .iter()
            .any(|(c, q)| c.eq_ignore_ascii_case("*") && *q > 0.0),
    }
}

/// No `q` means 1.0; a malformed `q` means 0.0 (excluded).
fn weight(params: &str) -> f32 {
    split_top_level(params, ';')
        .iter()
        .filter_map(|p| p.split_once('='))
        .find(|(n, _)| n.trim().eq_ignore_ascii_case("q"))
        .map_or(1.0, |(_, v)| qvalue(v.trim()).unwrap_or(0.0))
}

/// Out-of-range values are rejected, not clamped, so q=2 can't win at full weight.
fn qvalue(s: &str) -> Option<f32> {
    if s.is_empty() {
        return None;
    }
    let (int_part, frac) = match s.split_once('.') {
        Some((i, f)) => (i, Some(f)),
        None => (s, None),
    };
    let int = match int_part {
        "" | "0" => 0,
        "1" => 1,
        _ => return None,
    };
    if let Some(frac) = frac {
        // RFC grammar: up to three digits, only zeros after 1, and "0." or "1." are valid.
        if (int_part.is_empty() && frac.is_empty())
            || frac.len() > 3
            || !frac.bytes().all(|b| b.is_ascii_digit())
            || (int == 1 && !frac.bytes().all(|b| b == b'0'))
        {
            return None;
        }
    }
    let normalized = if int_part.is_empty() {
        format!("0{s}")
    } else {
        s.to_string()
    };
    normalized.parse::<f32>().ok()
}

/// Skips delimiters inside quoted strings, honoring backslash escapes.
fn find_top_level(s: &str, delim: char) -> Option<usize> {
    let mut in_quotes = false;
    let mut escaped = false;
    // A quoted-string can only start a parameter value, i.e. right after `=`.
    let mut prev = None;
    for (i, c) in s.char_indices() {
        if in_quotes {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_quotes = false;
            }
        } else if c == '"' && prev == Some('=') {
            in_quotes = true;
        } else if c == delim {
            return Some(i);
        }
        if !c.is_whitespace() {
            prev = Some(c);
        }
    }
    None
}

fn split_top_level(s: &str, delim: char) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    while let Some(i) = find_top_level(&s[start..], delim) {
        parts.push(&s[start..start + i]);
        start += i + delim.len_utf8();
    }
    parts.push(&s[start..]);
    parts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_negotiate_accept_table() {
        let cases: Vec<(&[&str], Option<AcceptType>)> = vec![
            (&[ACCEPT_STATUS_LISTS_HEADER_JWT], Some(AcceptType::Jwt)),
            (&[ACCEPT_STATUS_LISTS_HEADER_CWT], Some(AcceptType::Cwt)),
            (&["*/*"], Some(AcceptType::Jwt)),
            (&["application/*"], Some(AcceptType::Jwt)),
            (
                &["application/statuslist+jwt, application/statuslist+cwt;q=0.5"],
                Some(AcceptType::Jwt),
            ),
            (
                &["application/statuslist+cwt;q=0.5, application/statuslist+jwt;q=0.8"],
                Some(AcceptType::Jwt),
            ),
            (
                &["application/statuslist+cwt;q=0.9, application/statuslist+jwt;q=0.8"],
                Some(AcceptType::Cwt),
            ),
            (
                &["application/statuslist+cwt;q=0, application/statuslist+jwt"],
                Some(AcceptType::Jwt),
            ),
            (
                &["application/statuslist+jwt;q=0, application/statuslist+cwt;q=0"],
                None,
            ),
            (
                &["application/statuslist+jwt;q=0, */*"],
                Some(AcceptType::Cwt),
            ),
            (
                &["application/statuslist+cwt;q=0, application/*"],
                Some(AcceptType::Jwt),
            ),
            (
                &["application/statuslist+cwt;q=0, */*;q=0.9"],
                Some(AcceptType::Jwt),
            ),
            (
                &["application/statuslist+jwt; charset=utf-8"],
                Some(AcceptType::Jwt),
            ),
            (
                &["application/statuslist+jwt;profile=v2;q=1"],
                Some(AcceptType::Jwt),
            ),
            (&["Application/StatusList+JWT"], Some(AcceptType::Jwt)),
            (&["APPLICATION/STATUSLIST+CWT"], Some(AcceptType::Cwt)),
            (
                &["application/statuslist+cwt;Q=0.5, application/statuslist+jwt"],
                Some(AcceptType::Jwt),
            ),
            (
                &["application/statuslist+cwt; q = 0.5 , application/statuslist+jwt"],
                Some(AcceptType::Jwt),
            ),
            (&["application/statuslist+cwt;q=banana"], None),
            (
                &["application/statuslist+cwt;q=2, application/statuslist+jwt"],
                Some(AcceptType::Jwt),
            ),
            (&["application/statuslist+cwt;q=2"], None),
            (&["application/statuslist+cwt;q=1.5"], None),
            (
                &["application/statuslist+cwt;q=1.000"],
                Some(AcceptType::Cwt),
            ),
            (
                &["application/statuslist+cwt;q=.2, application/statuslist+jwt"],
                Some(AcceptType::Jwt),
            ),
            (&["application/statuslist+cwt;q=NaN"], None),
            (&["application/statuslist+cwt;q=inf"], None),
            (&["application/statuslist+cwt;q=-0.5"], None),
            (&["application/statuslist+cwt;q=1e2"], None),
            (&["application/statuslist+cwt;q=1."], Some(AcceptType::Cwt)),
            (&["application/statuslist+cwt;q=."], None),
            (
                &["application/statuslist+jwt;profile=\"a,b\";q=0, \
                     application/statuslist+cwt;q=0.5"],
                Some(AcceptType::Cwt),
            ),
            (
                &["application/statuslist+jwt;q=0.9, \
                     application/statuslist+cwt;profile=\"a;q=1\";q=0"],
                Some(AcceptType::Jwt),
            ),
            (
                &["text/\"html, application/statuslist+jwt"],
                Some(AcceptType::Jwt),
            ),
            (&["text/html"], None),
            (&["application/json"], None),
            (&[""], Some(AcceptType::Jwt)),
            (&["", ","], Some(AcceptType::Jwt)),
            (&["*/*;q=0"], None),
            (
                &["application/statuslist+cwt;q=1, application/statuslist+jwt;q=1"],
                Some(AcceptType::Jwt),
            ),
            (
                &["text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2"],
                Some(AcceptType::Jwt),
            ),
            (
                &["text/html", "application/statuslist+cwt;q=0.9"],
                Some(AcceptType::Cwt),
            ),
        ];

        for (fields, expected) in cases {
            assert_eq!(
                negotiate_accept(fields.iter().copied()),
                expected,
                "Accept: {fields:?}"
            );
        }

        assert_eq!(negotiate_accept([]), Some(AcceptType::Jwt));
    }

    #[test]
    fn test_accepts_gzip_simple() {
        let mut h = HeaderMap::new();
        h.insert(header::ACCEPT_ENCODING, "gzip".parse().unwrap());
        assert!(client_accepts_gzip(&h));
    }

    #[test]
    fn test_accepts_gzip_with_qvalue() {
        let mut h = HeaderMap::new();
        h.insert(header::ACCEPT_ENCODING, "gzip;q=0.8".parse().unwrap());
        assert!(client_accepts_gzip(&h));
    }

    #[test]
    fn test_accepts_gzip_dot2_shorthand() {
        let mut h = HeaderMap::new();
        h.insert(header::ACCEPT_ENCODING, "gzip;q=.2".parse().unwrap());
        assert!(client_accepts_gzip(&h));
    }

    #[test]
    fn test_rejects_gzip_uppercase_q0() {
        let mut h = HeaderMap::new();
        h.insert(header::ACCEPT_ENCODING, "gzip;Q=0".parse().unwrap());
        assert!(!client_accepts_gzip(&h));
    }

    #[test]
    fn test_rejects_gzip_malformed_q() {
        let mut h = HeaderMap::new();
        h.insert(header::ACCEPT_ENCODING, "gzip;q=banana".parse().unwrap());
        assert!(!client_accepts_gzip(&h));
    }

    #[test]
    fn test_rejects_gzip_q0() {
        let mut h = HeaderMap::new();
        h.insert(header::ACCEPT_ENCODING, "gzip;q=0".parse().unwrap());
        assert!(!client_accepts_gzip(&h));
    }

    #[test]
    fn test_rejects_gzip_q0_with_wildcard_accept() {
        let mut h = HeaderMap::new();
        h.insert(header::ACCEPT_ENCODING, "gzip;q=0, *".parse().unwrap());
        assert!(!client_accepts_gzip(&h));
    }

    #[test]
    fn test_accepts_via_wildcard_only() {
        let mut h = HeaderMap::new();
        h.insert(header::ACCEPT_ENCODING, "*".parse().unwrap());
        assert!(client_accepts_gzip(&h));
    }

    #[test]
    fn test_accepts_via_wildcard_q1() {
        let mut h = HeaderMap::new();
        h.insert(header::ACCEPT_ENCODING, "*;q=1".parse().unwrap());
        assert!(client_accepts_gzip(&h));
    }

    #[test]
    fn test_rejects_wildcard_q0() {
        let mut h = HeaderMap::new();
        h.insert(header::ACCEPT_ENCODING, "*;q=0".parse().unwrap());
        assert!(!client_accepts_gzip(&h));
    }

    #[test]
    fn test_rejects_when_header_absent() {
        let h = HeaderMap::new();
        assert!(!client_accepts_gzip(&h));
    }

    #[test]
    fn test_multiple_accept_encoding_lines() {
        let mut h = HeaderMap::new();
        h.append(header::ACCEPT_ENCODING, "deflate".parse().unwrap());
        h.append(header::ACCEPT_ENCODING, "gzip".parse().unwrap());
        assert!(client_accepts_gzip(&h));
    }

    #[test]
    fn test_case_insensitive_gzip() {
        let mut h = HeaderMap::new();
        h.insert(header::ACCEPT_ENCODING, "GZIP".parse().unwrap());
        assert!(client_accepts_gzip(&h));
    }

    #[test]
    fn test_accept_type_media_type_matches_constants() {
        assert_eq!(AcceptType::Jwt.media_type(), ACCEPT_STATUS_LISTS_HEADER_JWT);
        assert_eq!(AcceptType::Cwt.media_type(), ACCEPT_STATUS_LISTS_HEADER_CWT);
        assert_eq!(AcceptType::ALL, [AcceptType::Jwt, AcceptType::Cwt]);
    }
}
