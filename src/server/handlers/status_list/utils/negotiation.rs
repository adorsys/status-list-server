use axum::http::{HeaderMap, header};

use super::constants::{ACCEPT_STATUS_LISTS_HEADER_CWT, ACCEPT_STATUS_LISTS_HEADER_JWT};

/// The status-list token formats this endpoint can serve.
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

    /// RFC 9110 §12.5.1 precedence of `range` for this type: exact >
    /// `application/*` > `*/*`.
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

/// Negotiate the `Accept` header per RFC 9110 §12.5.1 and pick a supported
/// status-list media type.
///
/// `fields` is every `Accept` field line: RFC 9110 §5.3 folds multiple field
/// lines into one comma-separated list, so each line is a separate element and
/// the whole set is evaluated together.
///
/// Deliberately parameter-agnostic (a non-RFC policy): media parameters other
/// than `q` (for example `profile=v2`) are ignored for matching, so
/// `application/statuslist+jwt;profile=v2` is treated the same as the
/// parameter-free `application/statuslist+jwt`. This is a documented deviation
/// from RFC 9110 §12.5.1, which would match a range only against a
/// representation carrying the identical parameters. The server serves exactly
/// two un-parameterized representations today, so parameter equality would
/// always fail to match and every parameterized range would be ignored — that
/// is more surprising, and more likely to produce spurious `406`s, than the
/// parameter-agnostic reading. Revisit this if a parameterized status-list
/// variant is ever introduced.
///
/// Returns the supported type with the highest effective `q`. On a tie — or a
/// wildcard range, or no field lines at all, which the spec treats as `*/*` —
/// JWT wins. No supported type is acceptable only when every matching range has
/// `q=0` (or no range matches), which the caller turns into `406 Not
/// Acceptable`.
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
        // Absent, empty, or only empty list elements: no preference.
        return Some(AcceptType::Jwt);
    }

    // Per type: (precedence, q) of the most specific matching range. A more
    // specific range (`application/*` or an exact type) shadows a wildcard, so
    // an explicit `q=0` exclusion is never overridden by `*/*` (RFC 9110
    // §12.5.1 specificity).
    let mut best: [Option<(u8, f32)>; 2] = [None; 2];
    for range in ranges {
        // Media parameters (e.g. `profile`) may carry quoted strings, and a
        // quoted value can itself contain `;` or `,` that are data, not
        // delimiters. Split the range off its parameters at the first *top
        // level* `;` only, so those embedded characters survive.
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

/// Whether the client will accept a `gzip` content-coding, per `Accept-Encoding`
/// (RFC 9110 §12.5.3). An explicit `gzip` entry with `q > 0` (or no `q`)
/// accepts it; `q=0` excludes it. If `gzip` is not listed, a matching `*`
/// wildcard accepts it. Uses the same weight parser as `Accept`, so `Q=`/OWS
/// around `=` and `.2`-style shorthands behave identically (see [`weight`]).
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

/// Parse an RFC 9110 `qvalue`, allowing the common leading-dot shorthand
/// (`.2` == 0.2). Rejects anything malformed *or outside `[0, 1]`* rather than
/// clamping, so an invalid range such as `q=2` or `q=1.5` is excluded instead
/// of winning at full preference (RFC 9110 §12.4.2; issue #576).
fn qvalue(s: &str) -> Option<f32> {
    if s.is_empty() {
        return None;
    }
    // A value beginning with `1` may only carry trailing zeros (`1`, `1.000`).
    let (int_part, frac) = match s.split_once('.') {
        Some((i, f)) => (i, Some(f)),
        None => (s, None),
    };
    let int = match int_part {
        // The `.2` shorthand and plain `0`/`1`.
        "" | "0" => 0,
        "1" => 1,
        _ => return None,
    };
    if let Some(frac) = frac {
        // Up to three digits, digits only; after `1` only zeros are allowed.
        // `0.` and `1.` are valid (`0*3DIGIT`); only a bare `.` has no digits.
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

/// Index of the first `delim` at the top level — outside any RFC 9110 quoted
/// string. A backslash escape inside a quote is honoured so `\"` does not close
/// the string.
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

/// Split `s` on `delim` at the top level (outside quoted strings), so a `,` or
/// `;` inside a quoted media-parameter value is data, not a list separator.
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
        // (Accept field lines, expected outcome)
        let cases: Vec<(&[&str], Option<AcceptType>)> = vec![
            // Current exact-match cases still resolve.
            (&[ACCEPT_STATUS_LISTS_HEADER_JWT], Some(AcceptType::Jwt)),
            (&[ACCEPT_STATUS_LISTS_HEADER_CWT], Some(AcceptType::Cwt)),
            // Wildcards: */* and application/* serve JWT.
            (&["*/*"], Some(AcceptType::Jwt)),
            (&["application/*"], Some(AcceptType::Jwt)),
            // Comma-separated lists with q values.
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
            // q=0 excludes a type.
            (
                &["application/statuslist+cwt;q=0, application/statuslist+jwt"],
                Some(AcceptType::Jwt),
            ),
            (
                &["application/statuslist+jwt;q=0, application/statuslist+cwt;q=0"],
                None,
            ),
            // A wildcard must NOT override an explicit q=0 exclusion (RFC 9110
            // §12.5.1 specificity).
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
            // Parameters other than q are ignored for matching (documented
            // parameter-agnostic policy).
            (
                &["application/statuslist+jwt; charset=utf-8"],
                Some(AcceptType::Jwt),
            ),
            (
                &["application/statuslist+jwt;profile=v2;q=1"],
                Some(AcceptType::Jwt),
            ),
            // Case-insensitive type and subtype.
            (&["Application/StatusList+JWT"], Some(AcceptType::Jwt)),
            (&["APPLICATION/STATUSLIST+CWT"], Some(AcceptType::Cwt)),
            // The q parameter name is case-insensitive; OWS around `;` is
            // tolerated (the parser also trims around `=`).
            (
                &["application/statuslist+cwt;Q=0.5, application/statuslist+jwt"],
                Some(AcceptType::Jwt),
            ),
            (
                &["application/statuslist+cwt; q = 0.5 , application/statuslist+jwt"],
                Some(AcceptType::Jwt),
            ),
            // A malformed or out-of-range weight is handled conservatively: it
            // excludes its range. `q=banana` is malformed; `q=2` / `q=1.5` are
            // outside the RFC 9110 `[0,1]` range and must not win at full
            // preference — including when the invalid range is the *only*
            // match, which must yield 406 rather than the (previously
            // clamped-to-1) type.
            (&["application/statuslist+cwt;q=banana"], None),
            (
                &["application/statuslist+cwt;q=2, application/statuslist+jwt"],
                Some(AcceptType::Jwt),
            ),
            // An invalid weight as the only matching range -> nothing acceptable.
            (&["application/statuslist+cwt;q=2"], None),
            (&["application/statuslist+cwt;q=1.5"], None),
            (
                &["application/statuslist+cwt;q=1.000"],
                Some(AcceptType::Cwt),
            ),
            // Plain decimals only: no NaN, inf, sign or exponent ever slips
            // through, but the common `.2` shorthand still parses.
            (
                &["application/statuslist+cwt;q=.2, application/statuslist+jwt"],
                Some(AcceptType::Jwt),
            ),
            (&["application/statuslist+cwt;q=NaN"], None),
            (&["application/statuslist+cwt;q=inf"], None),
            (&["application/statuslist+cwt;q=-0.5"], None),
            (&["application/statuslist+cwt;q=1e2"], None),
            // A trailing dot with no digits is malformed, but `0.` / `1.` are
            // valid per the RFC 9110 grammar (`0*3DIGIT` after the dot).
            (&["application/statuslist+cwt;q=1."], Some(AcceptType::Cwt)),
            (&["application/statuslist+cwt;q=."], None),
            // Quoted media parameters: a `,` or `;q=` inside a quoted value is
            // data, not a list separator / weight (RFC 9110 §5.6.4).
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
            // A stray quote (not a parameter value) must not swallow the rest
            // of the range: the `,` after it stays a top-level separator.
            (
                &["text/\"html, application/statuslist+jwt"],
                Some(AcceptType::Jwt),
            ),
            // Unsupported types.
            (&["text/html"], None),
            (&["application/json"], None),
            // Empty field lines are treated as an absent header -> JWT.
            (&[""], Some(AcceptType::Jwt)),
            (&["", ","], Some(AcceptType::Jwt)),
            // A wildcard excluded by q=0 -> nothing acceptable.
            (&["*/*;q=0"], None),
            // A tie with CWT listed first still resolves to JWT (tie-break order).
            (
                &["application/statuslist+cwt;q=1, application/statuslist+jwt;q=1"],
                Some(AcceptType::Jwt),
            ),
            // The legacy JDK default Accept header.
            (
                &["text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2"],
                Some(AcceptType::Jwt),
            ),
            // Multiple field lines form one list (RFC 9110 §5.3).
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

        // No field lines at all -> JWT.
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
        // Regression: the old `q=`-only parser ignored `Q=0` and served gzip
        // anyway, because it treated the entry as having no q at all.
        let mut h = HeaderMap::new();
        h.insert(header::ACCEPT_ENCODING, "gzip;Q=0".parse().unwrap());
        assert!(!client_accepts_gzip(&h));
    }

    #[test]
    fn test_rejects_gzip_malformed_q() {
        // A malformed `q` excludes the coding: the response goes out
        // uncompressed rather than assuming the client accepts gzip.
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
