mod aggregation_id;
mod contention;
mod credentials;
mod fixtures;
#[cfg(feature = "sqlite")]
mod history;
mod hosted;
mod key_id;
mod list_quota;
mod migrations;
mod status_list;

#[test]
fn connection_acquisition_failures_are_classified_as_unavailable() {
    let error = super::find_err(sea_orm::DbErr::ConnectionAcquire(
        sea_orm::ConnAcquireErr::Timeout,
    ));
    assert!(matches!(
        error,
        crate::outbound::sql::RepositoryError::Unavailable
    ));
}
