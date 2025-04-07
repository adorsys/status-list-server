use std::process::Command;

pub fn setup_cert(domain: &str) {
    let status = Command::new("./certbot_setup.sh")
        .arg(domain)
        .status()
        .expect("Failed to run certbot script");

    if status.success() {
        println!("Certificate setup successful!");
    } else {
        eprintln!("Certbot script failed with status: {}", status);
    }
}
