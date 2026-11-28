// Fixture for engine/myelin_engine/rules/sast/rust.yaml (opengrep --test). Not compiled.
fn run(pool: &PgPool, id: &str) {
    // ruleid: nervve.rust.sql-injection
    let r = sqlx::query(&format!("SELECT * FROM users WHERE id = {}", id));
    // ok: nervve.rust.sql-injection
    let s = sqlx::query("SELECT * FROM users WHERE id = $1").bind(id);
    // ruleid: nervve.rust.command-injection
    Command::new("sh").arg("-c").arg(format!("ls {}", id));
    // ok: nervve.rust.command-injection
    Command::new("ls").arg(id);
    // ruleid: nervve.rust.tls-verification-disabled
    let c = reqwest::Client::builder().danger_accept_invalid_certs(true);
    // ruleid: nervve.rust.weak-crypto
    let h = md5::compute(b"x");
    // ruleid: nervve.rust.insecure-random
    let rng = StdRng::seed_from_u64(42);
}
