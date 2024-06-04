A thin wrapper around [tokio-rustls](https://docs.rs/tokio-rustls) to make it a little bit easier to use.

### Example

```rust
use tokio_tls_listener::{TlsListener, load_tls_config};
async {
    let conf = load_tls_config("./key.pem", "./cert.pem").unwrap();
    let listener = TlsListener::bind("127.0.0.1:4433", conf).await.unwrap();
    loop {
        if let Ok((stream, addr)) = listener.accept_tls().await {
            // ...
        }
    }
};
```
