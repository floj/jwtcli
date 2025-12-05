# jwtcli 🔐

A tiny CLI to pretty-print JSON Web Tokens (JWTs).

Decodes and formats header and payload. Additionally annotates standard time-based claims (`iat`, `nbf`, `exp`) with human-readable timestamps in your local timezone.

## Installation 📦

### Build from source 🏗️

Clone and build:

```sh
git clone https://github.com/floj/jwtcli.git
cd jwtcli
./build.sh
```

The resulting binary will be `./jwtcli` (or `./jwtcli.exe` on Windows).

### Go install 🚀

```sh
go install github.com/floj/jwtcli@latest
```

This places `jwtcli` in your `GOBIN` (usually `~/go/bin`). Ensure it is on your `PATH`.

## Usage 🧭

You can pass a JWT via arguments or pipe it via stdin.

### From arguments 💬

```sh
jwtcli <jwt1> [<jwt2> ...]
```

### From stdin 📥

```sh
echo "$JWT" | jwtcli
# or
cat tokens.txt | jwtcli
```

## Examples 🧪

```sh
jwtcli eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0IiwiaWF0IjoxNzAwMDAwMDB9.signature
```

Output:

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
{
  "iat": 170000000,
  "sub": "1234"
}
// iat: 1975-05-22 15:13:20 +0100 CET
```

## Build script 🛠️

`./build.sh` builds a statically linked binary.

```sh
./build.sh
```

## Development 🧑‍💻

```sh
# Run directly
go run ./

# Build
go build ./
```

## License 📄

MIT, see [LICENSE](./LICENSE).
