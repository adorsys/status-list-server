diesel::table! {
    credentials (id) {
        id -> Int4,
        issuer -> Text,
        public_key -> Bytea,
        alg -> Text,
    }
}

diesel::table! {
    status_list_tokens (id) {
        id -> Int4,
        issuer -> Text,
        status_list_token -> Nullable<Text>,
    }
}

diesel::allow_tables_to_appear_in_same_query!(
    credentials,
    status_list_tokens,
);
