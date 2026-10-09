use std::process::ExitCode;

fn main() -> ExitCode {
    match color_eyre::install().and_then(|()| xtask::run()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error:?}");
            ExitCode::FAILURE
        }
    }
}
