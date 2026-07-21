//! Bug condition exploration test for Docker image pull failures.
//!
//! **Validates: Requirements 1.1, 1.2, 1.3, 1.4**
//!
//! This test is designed to FAIL on unfixed code - failure confirms the bug exists.
//! The bug manifests as either:
//! - HTTP 403 errors when pulling from ghcr.io (Pebble images)
//! - I/O errors when pulling from Docker Hub (MySQL image)
//!
//! # Bug Condition
//! When testcontainers attempts to pull images from ghcr.io or Docker Hub,
//! the pull operation fails with HTTP 403 or I/O errors respectively.

use testcontainers::{
    GenericImage, ImageExt,
    core::IntoContainerPort,
    runners::AsyncRunner,
};

/// Pebble ACME test server image
const PEBBLE_IMAGE: &str = "ghcr.io/letsencrypt/pebble";
const PEBBLE_TAG: &str = "2.10";

/// Pebble challenge test server image
const CHALLTESTSRV_IMAGE: &str = "ghcr.io/letsencrypt/pebble-challtestsrv";
const CHALLTESTSRV_TAG: &str = "2.10";

/// MySQL image as referenced in docker-compose.yml
const MYSQL_IMAGE: &str = "mysql";
const MYSQL_TAG: &str = "9.2";

/// Test that Pebble image can be pulled from ghcr.io.
///
/// **Bug Condition**: This test is expected to FAIL with HTTP 403 error
/// when the bug is present, proving the bug exists.
///
/// **Expected failure message**: HTTP 403 from ghcr.io when attempting
/// to pull `ghcr.io/letsencrypt/pebble:2.10`
#[tokio::test]
async fn bug_condition_pebble_image_pull() {
    let result = GenericImage::new(PEBBLE_IMAGE, PEBBLE_TAG)
        .with_exposed_port(14000.tcp())
        .start()
        .await;

    // If we get here, either:
    // 1. The bug is fixed (test passes = good)
    // 2. The image was already cached locally
    //
    // The bug is confirmed when this test FAILS with HTTP 403
    assert!(
        result.is_ok(),
        "Pebble image pull failed - this may indicate the bug is present. \
         Error: {:?}",
        result.err()
    );
}

/// Test that Pebble challenge test server image can be pulled from ghcr.io.
///
/// **Bug Condition**: This test is expected to FAIL with HTTP 403 error
/// when the bug is present, proving the bug exists.
///
/// **Expected failure message**: HTTP 403 from ghcr.io when attempting
/// to pull `ghcr.io/letsencrypt/pebble-challtestsrv:2.10`
#[tokio::test]
async fn bug_condition_challtestsrv_image_pull() {
    let result = GenericImage::new(CHALLTESTSRV_IMAGE, CHALLTESTSRV_TAG)
        .with_exposed_port(8055.tcp())
        .start()
        .await;

    // The bug is confirmed when this test FAILS with HTTP 403
    assert!(
        result.is_ok(),
        "Challtestsrv image pull failed - this may indicate the bug is present. \
         Error: {:?}",
        result.err()
    );
}

/// Test that MySQL image with explicit tag can be pulled from Docker Hub.
///
/// **Bug Condition**: This test is expected to FAIL with I/O error
/// when the bug is present, proving the bug exists.
///
/// **Expected failure message**: I/O error from Docker Hub when attempting
/// to pull `mysql:9.2`
#[tokio::test]
async fn bug_condition_mysql_image_pull() {
    let result = GenericImage::new(MYSQL_IMAGE, MYSQL_TAG)
        .with_exposed_port(3306.tcp())
        .start()
        .await;

    // The bug is confirmed when this test FAILS with I/O error
    assert!(
        result.is_ok(),
        "MySQL image pull failed - this may indicate the bug is present. \
         Error: {:?}",
        result.err()
    );
}
