A thin wrapper around [tokio-rustls](https://docs.rs/tokio-rustls) to make it a little bit easier to use.

### Example

```rust
use tokio_tls_listener::{TlsListener, tls_config};
async {
    let conf = tls_config("./cert.pem", "./key.pem").unwrap();
    let listener = TlsListener::bind("127.0.0.1:4433", conf).await.unwrap();
    loop {
        let Ok((stream, addr)) = listener.accept_tls().await else { continue };
        // ...
    }
};
```
