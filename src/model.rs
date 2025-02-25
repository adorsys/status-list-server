use diesel::{prelude::{Insertable, Queryable}, Selectable};
pub struct StatusList {
    pub bits: u8,
    pub lst: String,

}

#[derive(Queryable, Insertable, Selectable)]
#[diesel(table_name = crate::database::schema::credentials)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Credentials {
    public_key: Vec<u8>,
    alg: String
}