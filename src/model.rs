use diesel::{
    prelude::{Insertable, Queryable},
    Selectable,
};

#[derive(Default)]
pub struct StatusList {
    pub bits: u8,
    pub lst: String,
}

#[derive(Queryable, Insertable, Selectable)]
#[diesel(table_name = crate::database::schema::credentials)]
#[diesel(check_for_backend(diesel::pg::Pg))]
#[derive(Default)]
pub struct Credentials {
    issuer: String,
    public_key: Vec<u8>,
    alg: String,
}

use diesel::prelude::*;
use diesel::associations::HasTable;

impl HasTable for Credentials {
    type Table = crate::database::schema::credentials::table;

    fn table() -> Self::Table {
        crate::database::schema::credentials::table
    }
}