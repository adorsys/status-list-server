use diesel::helper_types::{AsSelect, Eq};
use diesel::query_builder::AsQuery;
use diesel::query_dsl::methods::FilterDsl;
use diesel::query_dsl::methods::SelectDsl;
use diesel::{
    associations::HasTable, pg::Pg, prelude::Insertable, query_builder::QueryId,
    query_dsl::methods::LimitDsl,
};
use diesel::{SelectableHelper, Table};

use diesel_async::AsyncPgConnection;
use diesel_async::{methods::LoadQuery, RunQueryDsl};

use crate::model::Credentials;

use super::schema::{self, credentials};
use super::{connection::Database, errors::RepositoryError};

/// Database Repository
trait Repository<C, T>
where
    <T as HasTable>::Table: QueryId + Send + 'static,
    T: diesel::associations::HasTable + diesel::Selectable<Pg>,
    <T::Table as diesel::QuerySource>::FromClause:
        Send + diesel::query_builder::QueryFragment<diesel::pg::Pg>,
    C: diesel::Insertable<T::Table>,
    <C as Insertable<<T as HasTable>::Table>>::Values: QueryId + Send,
    C::Values: diesel::insertable::CanInsertInSingleQuery<diesel::pg::Pg>
        + diesel::query_builder::QueryFragment<diesel::pg::Pg>,
{
    /// Store a single entity in the database
    async fn store(entity: C, conn_pool: &Database) -> Result<(), RepositoryError> {
        let mut conn = conn_pool
            .get()
            .await
            .map_err(|_| RepositoryError::PoolError)?;
        diesel::insert_into(T::table())
            .values(entity)
            .execute(&mut conn)
            .await
            .map_err(|_| RepositoryError::InsertError)?;
        Ok(())
    }

    /// find by id
    async fn find_by<'query, S, U>(
        id: U,
        conn_pool: &Database,
        column: S,
    ) -> Result<Self, RepositoryError>
    where
        S: diesel::Expression + diesel::ExpressionMethods + Send,
        <S as diesel::Expression>::SqlType: diesel::sql_types::SqlType + Send,
        U: diesel::expression::AsExpression<<S as diesel::Expression>::SqlType> + Send + Copy,
        T::Table: diesel::Table + diesel::QuerySource + diesel::SelectableHelper<Pg> + Send,
        T: diesel::Selectable<Pg> + Send + 'static,
        T::Table: FilterDsl<Eq<S, U>> + Send,
        diesel::dsl::FindBy<T::Table, S, U>: SelectDsl<AsSelect<Self, Pg>> + Send,
        diesel::dsl::Select<diesel::dsl::FindBy<T::Table, S, U>, AsSelect<Self, Pg>>:
            RunQueryDsl<AsyncPgConnection> + LimitDsl + Send,
        diesel::dsl::Limit<
            diesel::dsl::Select<diesel::dsl::FindBy<T::Table, S, U>, AsSelect<Self, Pg>>,
        >: LoadQuery<'query, AsyncPgConnection, Self> + Send + 'query,

        <<T::Table as FilterDsl<Eq<S, U>>>::Output as SelectDsl<AsSelect<Self, Pg>>>::Output: Send,
        <T::Table as FilterDsl<Eq<S, U>>>::Output:
            SelectDsl<AsSelect<Self, Pg>> + LimitDsl + Send + Sync,
        <<T::Table as FilterDsl<Eq<S, U>>>::Output as SelectDsl<AsSelect<Self, Pg>>>::Output:
            Send + Sync + LoadQuery<'query, AsyncPgConnection, Self>,
        Self: diesel::Selectable<Pg> + Sized + Send + 'static,
        <Self as diesel::Selectable<Pg>>::SelectExpression: QueryId + Send,
        T::Table: diesel::Table + Send,
        T::Table: diesel::QueryDsl + Send,
        S: diesel::Column + Send,
        Self: Send + Sync,
    {
        let mut conn = conn_pool
            .get()
            .await
            .map_err(|_| RepositoryError::PoolError)?;

        let cred = <T as HasTable>::table()
            .filter(column.eq(id))
            .select(Self::as_select())
            .first::<Self>(&mut conn)
            .await
            .map_err(|_| RepositoryError::FetchError)?;

        Ok(cred)
    }
}

impl Repository<Credentials, Credentials> for Credentials {

}




#[cfg(test)]
mod test {

}
