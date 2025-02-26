use diesel::helper_types::{AsSelect, Eq, FindBy, Limit, Select};
use diesel::query_dsl::methods::FilterDsl;
use diesel::Expression;
use diesel::{
    associations::HasTable, pg::Pg, prelude::Insertable, query_builder::QueryId,
    query_dsl::methods::LimitDsl,
};

use diesel_async::{methods::LoadQuery, RunQueryDsl};

use super::{connection::Database, errors::RepositoryError};

/// Database Repository
trait Repository<C, T>
where
    <T as HasTable>::Table: QueryId + Send + 'static,
    T: diesel::associations::HasTable,
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
            .execute(&mut conn);
        Ok(())
    }

    /// find by id
    async fn find_by<'query, S, U>(
        id: U,
        conn_pool: &Database,
        column: S,
    ) -> Result<C, RepositoryError>
    where
        S: diesel::Expression + diesel::ExpressionMethods,
        <S as diesel::Expression>::SqlType: diesel::sql_types::SqlType,
        U: diesel::expression::AsExpression<<S as diesel::Expression>::SqlType>,
        T: diesel::Table + diesel::QuerySource + diesel::SelectableHelper<Pg>,
        T::Table: diesel::QueryDsl + FilterDsl<Eq<S, U>>,
        C: diesel::Selectable<Pg>,
    {
        let mut conn = conn_pool
            .get()
            .await
            .map_err(|_| RepositoryError::PoolError)?;
    
        let cred = T::table()
            .filter(column.eq(id))
            .select(T::as_select())
            .first(&mut conn)
            .await
            .map_err(|_| RepositoryError::FetchError)?;
    
        Ok(cred)
    }
}
