# ADR 0002: Status List Allocation and Default Initialisation

## Status

Accepted

## Context

OAuth Status List draft-21 §13.3 requires a Status Issuer to prevent unintended
double allocation of a `(uri, idx)` pair. It also recommends initialising the
Status List byte array with a default value so unused entries are
indistinguishable from valid entries and the number of issued tokens is not
revealed by list growth.

The previous management API let callers write arbitrary indices. The list grew
to the highest written index, duplicate indices in one request could collapse to
one value, and the server had no durable record of which indices had already
been handed out.

## Decision

The server owns index reservation through
`POST /api/v1/status-lists/{list_id}/allocations`. The repository records every
reserved `(list_id, idx)` pair, with SQL enforcing uniqueness via a composite
primary key. Allocation returns the lowest available indices in ascending order.

Publish accepts optional `size` and `default_status` fields. When `size` is
present, the status list is created at full rounded size and every entry is
initialised to `default_status`, defaulting to valid (`0`). The rounded size is
stored with the list so later updates reject writes past that bound with
`index_out_of_range`. Lists without `size` keep the legacy explicit growth
behaviour.

Duplicate indices in a single publish or update payload are rejected in the
domain model with `duplicate_index`, so the invariant does not depend on HTTP
handler validation.

## Consequences

Re-issued and batch-issued tokens can receive fresh entries by calling the
allocation endpoint before embedding `status_list.idx` in the referenced token.
Fixed-size lists no longer reveal the highest issued index through the compressed
array length. Operators may still use legacy growable lists by omitting `size`,
and explicit growth can be introduced separately as the §13.4 operation.
