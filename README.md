## Building and running:
1. clone this repo
2. `cargo build --target=wasm32-unknown-unknown --release`
3. `docker-compose up --build`

## Testing it Works
```bash
curl  -H localhost:18000
403 Access forbidden.

python  test_sign.py
200 Welcome to WASM land
```