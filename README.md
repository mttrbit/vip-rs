# Symantec VIP client

Vip is a Rust library for the Symantec VIP API. At the moment this library is a simple proof of concept.

# Installation

Add the following to your `Cargo.toml` file:

```toml
[dependencies]
vip = { git = "https://github.com/mttrbit/vip-rs", branch = "main"}
```

Vip is built with Rust 1.48.

# Usage


```rust,ignore
use vip::{CodeResponse, fetch_security_code};

let user = "your.email%40example.com";
let request_id = "yOur12343rEquEstIDHerE";
let header_referer = "https:://subdomain.example.com";

let response = fetch_security_code::<CodeResponse>(user, request_id, header_referer);
```
