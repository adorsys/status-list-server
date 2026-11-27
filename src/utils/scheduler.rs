//! Background jobs on cron schedules, evaluated in UTC.

use std::{future::Future, sync::Arc, time::Duration};

use croner::{
    Cron, CronError,
    parser::{CronParser, Seconds},
};
use jiff::{Timestamp, tz::TimeZone};
use time::OffsetDateTime;
use tokio::task::JoinHandle;

pub(crate) type Clock = Arc<dyn Fn() -> OffsetDateTime + Send + Sync>;

// Short sleeps, so a suspend or a wall-clock jump is noticed within a minute.
const MAX_SLEEP: Duration = Duration::from_secs(60);

#[derive(Debug)]
pub(crate) struct CronSchedule(Cron);

impl CronSchedule {
    /// Parses a cron expression with seconds first and an optional year.
    pub(crate) fn parse(expression: &str) -> Result<Self, CronError> {
        CronParser::builder()
            .seconds(Seconds::Required)
            .dom_and_dow(true)
            // Keeps the `0/10` and `/10` step forms that croner 3 accepted.
            .sloppy_ranges(true)
            .build()
            .parse(expression)
            .map(Self)
    }

    /// Returns the first fire time strictly after `after`, if there is one.
    pub(crate) fn next_after(&self, after: OffsetDateTime) -> Option<OffsetDateTime> {
        let start = Timestamp::from_second(after.unix_timestamp())
            .ok()?
            .to_zoned_datetime(TimeZone::UTC);
        let next = self.0.find_next_occurrence(&start, false).ok()?;
        OffsetDateTime::from_unix_timestamp(next.timestamp().as_second()).ok()
    }
}

/// Runs `job` at each fire time without overlap; fire times missed in a suspend become one run.
pub(crate) fn spawn<F, Fut>(
    name: &'static str,
    schedule: CronSchedule,
    clock: Clock,
    mut job: F,
) -> JoinHandle<()>
where
    F: FnMut() -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move {
        let mut last_fire: Option<OffsetDateTime> = None;
        loop {
            let now = clock();
            let after = last_fire.map_or(now, |last| now.max(last));
            let Some(next) = schedule.next_after(after) else {
                tracing::error!(
                    job = name,
                    "Cron schedule has no future fire time; the job will not run again"
                );
                return;
            };
            loop {
                let now = clock();
                if now >= next {
                    break;
                }
                let wait = Duration::try_from(next - now).unwrap_or(Duration::ZERO);
                tokio::time::sleep(wait.min(MAX_SLEEP)).await;
            }
            last_fire = Some(next);
            if let Err(err) = tokio::spawn(job()).await {
                tracing::error!(job = name, "Scheduled job panicked: {err}");
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicI64, AtomicUsize, Ordering},
    };
    use std::time::Duration;

    use time::{OffsetDateTime, macros::datetime};

    use super::{Clock, CronSchedule, spawn};

    fn next(expression: &str, after: OffsetDateTime) -> Option<OffsetDateTime> {
        CronSchedule::parse(expression)
            .expect("expression should parse")
            .next_after(after)
    }

    fn paused_clock(start: OffsetDateTime, jump_secs: Arc<AtomicI64>) -> Clock {
        let origin = tokio::time::Instant::now();
        Arc::new(move || {
            start
                + (tokio::time::Instant::now() - origin)
                + time::Duration::seconds(jump_secs.load(Ordering::SeqCst))
        })
    }

    fn recording_job(
        clock: Clock,
        runs: Arc<Mutex<Vec<OffsetDateTime>>>,
    ) -> impl FnMut() -> std::future::Ready<()> + Send + 'static {
        move || {
            runs.lock().expect("runs lock").push(clock());
            std::future::ready(())
        }
    }

    #[test]
    fn default_schedule_fires_at_the_next_midnight() {
        assert_eq!(
            next("0 0 0 * * *", datetime!(2026-11-27 10:00 UTC)),
            Some(datetime!(2026-11-28 0:00 UTC))
        );
    }

    #[test]
    fn a_fire_time_is_not_returned_again() {
        assert_eq!(
            next("0 0 0 * * *", datetime!(2026-11-28 0:00 UTC)),
            Some(datetime!(2026-11-29 0:00 UTC))
        );
    }

    #[test]
    fn noon_schedule_fires_the_same_day_until_noon() {
        assert_eq!(
            next("0 0 12 * * *", datetime!(2026-11-27 11:59:59 UTC)),
            Some(datetime!(2026-11-27 12:00 UTC))
        );
        assert_eq!(
            next("0 0 12 * * *", datetime!(2026-11-27 12:00 UTC)),
            Some(datetime!(2026-11-28 12:00 UTC))
        );
    }

    #[test]
    fn month_end_skips_months_without_that_day() {
        assert_eq!(
            next("0 0 0 31 * *", datetime!(2026-04-15 0:00 UTC)),
            Some(datetime!(2026-05-31 0:00 UTC))
        );
    }

    #[test]
    fn leap_day_waits_for_the_next_leap_year() {
        assert_eq!(
            next("0 0 0 29 2 *", datetime!(2026-03-01 0:00 UTC)),
            Some(datetime!(2028-02-29 0:00 UTC))
        );
    }

    #[test]
    fn day_of_month_and_weekday_must_both_match() {
        assert_eq!(
            next("0 0 0 1 * MON", datetime!(2026-01-02 0:00 UTC)),
            Some(datetime!(2026-06-01 0:00 UTC))
        );
    }

    #[test]
    fn schedule_in_the_past_has_no_fire_time() {
        assert_eq!(
            next("0 0 0 1 1 * 2020", datetime!(2026-11-27 0:00 UTC)),
            None
        );
    }

    #[test]
    fn step_forms_croner_3_accepted_still_parse() {
        assert_eq!(
            next("0/30 * * * * *", datetime!(2026-11-27 10:00:05 UTC)),
            Some(datetime!(2026-11-27 10:00:30 UTC))
        );
    }

    #[test]
    fn five_field_and_malformed_expressions_are_rejected() {
        assert!(CronSchedule::parse("0 0 * * *").is_err());
        assert!(CronSchedule::parse("not a cron").is_err());
        assert!(CronSchedule::parse("").is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn runs_at_each_fire_time() {
        let clock = paused_clock(datetime!(2026-11-27 10:00:05 UTC), Arc::default());
        let runs = Arc::new(Mutex::new(Vec::new()));
        let schedule = CronSchedule::parse("*/10 * * * * *").expect("valid schedule");
        let handle = spawn(
            "test",
            schedule,
            clock.clone(),
            recording_job(clock, runs.clone()),
        );

        tokio::time::sleep(Duration::from_secs(30)).await;
        handle.abort();

        assert_eq!(
            *runs.lock().expect("runs lock"),
            vec![
                datetime!(2026-11-27 10:00:10 UTC),
                datetime!(2026-11-27 10:00:20 UTC),
                datetime!(2026-11-27 10:00:30 UTC),
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn runs_never_overlap() {
        let clock = paused_clock(datetime!(2026-11-27 10:00:05 UTC), Arc::default());
        let starts = Arc::new(Mutex::new(Vec::new()));
        let running = Arc::new(AtomicUsize::new(0));
        let most_at_once = Arc::new(AtomicUsize::new(0));
        let job = {
            let (clock, starts, running, most_at_once) = (
                clock.clone(),
                starts.clone(),
                running.clone(),
                most_at_once.clone(),
            );
            move || {
                starts.lock().expect("starts lock").push(clock());
                let (running, most_at_once) = (running.clone(), most_at_once.clone());
                async move {
                    let now_running = running.fetch_add(1, Ordering::SeqCst) + 1;
                    most_at_once.fetch_max(now_running, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_secs(25)).await;
                    running.fetch_sub(1, Ordering::SeqCst);
                }
            }
        };
        let schedule = CronSchedule::parse("*/10 * * * * *").expect("valid schedule");
        let handle = spawn("test", schedule, clock, job);

        tokio::time::sleep(Duration::from_secs(60)).await;
        handle.abort();

        assert_eq!(most_at_once.load(Ordering::SeqCst), 1);
        assert_eq!(
            *starts.lock().expect("starts lock"),
            vec![
                datetime!(2026-11-27 10:00:10 UTC),
                datetime!(2026-11-27 10:00:40 UTC),
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_panicking_job_does_not_stop_the_schedule() {
        let clock = paused_clock(datetime!(2026-11-27 10:00:05 UTC), Arc::default());
        let calls = Arc::new(AtomicUsize::new(0));
        let job = {
            let calls = calls.clone();
            move || {
                let call = calls.fetch_add(1, Ordering::SeqCst);
                async move {
                    if call == 0 {
                        panic!("first run fails");
                    }
                }
            }
        };
        let schedule = CronSchedule::parse("*/10 * * * * *").expect("valid schedule");
        let handle = spawn("test", schedule, clock, job);

        tokio::time::sleep(Duration::from_secs(30)).await;
        handle.abort();

        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn fire_times_missed_in_a_clock_jump_run_once() {
        let jump_secs = Arc::new(AtomicI64::new(0));
        let clock = paused_clock(datetime!(2026-11-27 10:00:30 UTC), jump_secs.clone());
        let runs = Arc::new(Mutex::new(Vec::new()));
        let schedule = CronSchedule::parse("0 * * * * *").expect("valid schedule");
        let handle = spawn(
            "test",
            schedule,
            clock.clone(),
            recording_job(clock, runs.clone()),
        );

        tokio::time::sleep(Duration::from_secs(1)).await;
        jump_secs.store(3600, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_secs(99)).await;
        handle.abort();

        assert_eq!(
            *runs.lock().expect("runs lock"),
            vec![
                datetime!(2026-11-27 11:01:00 UTC),
                datetime!(2026-11-27 11:02:00 UTC),
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_schedule_without_fire_times_ends_the_task() {
        let clock = paused_clock(datetime!(2026-11-27 10:00 UTC), Arc::default());
        let calls = Arc::new(AtomicUsize::new(0));
        let job = {
            let calls = calls.clone();
            move || {
                calls.fetch_add(1, Ordering::SeqCst);
                std::future::ready(())
            }
        };
        let schedule = CronSchedule::parse("0 0 0 1 1 * 2020").expect("valid schedule");

        tokio::time::timeout(Duration::from_secs(1), spawn("test", schedule, clock, job))
            .await
            .expect("task should end on its own")
            .expect("task should not panic");

        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}
