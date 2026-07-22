use std::process::Command;

fn main() {
    let task = std::env::args().nth(1);
    match task.as_deref() {
        Some("test") => cmd_test(),
        Some("lint") => cmd_lint(),
        Some("build") => cmd_build(),
        Some("compose") => cmd_compose(),
        Some("release") => cmd_release(),
        Some("doc") => cmd_doc(),
        Some("ci") => cmd_ci(),
        Some("help") | None => help(),
        Some(other) => {
            eprintln!("unknown task: {other}");
            help();
            std::process::exit(1);
        }
    }
}

fn help() {
    eprintln!("Usage: cargo xtask <task>");
    eprintln!();
    eprintln!("Tasks:");
    eprintln!("  test       Start db/redis/localstack and run the test suite");
    eprintln!("  lint       Run formatting, clippy, audit, and machete checks");
    eprintln!("  build      Build the workspace with all targets and features");
    eprintln!("  compose    Start docker compose services");
    eprintln!("  release    Build a release binary");
    eprintln!("  doc        Build documentation");
    eprintln!("  ci         Run the full CI pipeline locally");
}

fn run(program: &str, args: &[&str]) {
    let status = Command::new(program)
        .args(args)
        .status()
        .expect("failed to execute command");
    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
}

fn cmd_build() {
    println!("Building workspace...");
    run(
        "cargo",
        &["build", "--workspace", "--all-targets", "--all-features"],
    );
}

fn cmd_test() {
    println!("Starting required services...");
    run(
        "docker",
        &["compose", "up", "-d", "db", "redis", "localstack", "--wait"],
    );

    println!("Running tests...");
    run(
        "cargo",
        &[
            "nextest",
            "run",
            "--workspace",
            "--all-targets",
            "--all-features",
        ],
    );
}

fn cmd_lint() {
    println!("Checking code format...");
    run("cargo", &["fmt", "--all", "--check"]);

    println!("Running clippy...");
    run(
        "cargo",
        &[
            "clippy",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--",
            "-D",
            "warnings",
        ],
    );

    println!("Running cargo audit...");
    run("cargo", &["audit"]);

    println!("Checking unused dependencies...");
    run("cargo", &["machete", "--with-metadata"]);
}

fn cmd_compose() {
    run("docker", &["compose", "up", "--build", "--wait"]);
}

fn cmd_release() {
    run(
        "cargo",
        &["build", "--release", "--package", "status-list-server"],
    );
}

fn cmd_doc() {
    println!("Building documentation...");
    run(
        "cargo",
        &[
            "doc",
            "--workspace",
            "--all-features",
            "--no-deps",
            "--document-private-items",
        ],
    );
}

fn cmd_ci() {
    cmd_lint();
    cmd_build();
    cmd_doc();
    cmd_test();
    println!("CI pipeline completed successfully");
}
