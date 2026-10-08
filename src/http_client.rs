//! Shared bounded HTTP client for the public Polymarket adapters.

use std::time::Duration;

/// Maximum time allowed to establish a public API TCP/TLS connection.
pub const HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Maximum time allowed for one complete public API request.
pub const HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Construct the bounded default client used only by convenience constructors.
/// Injection constructors intentionally continue to use their caller's client unchanged.
pub fn default_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(HTTP_CONNECT_TIMEOUT)
        .timeout(HTTP_REQUEST_TIMEOUT)
        .build()
        .expect("static Polymarket HTTP client configuration is valid")
}
