# fexe — exe alternative 

A portable, self-contained package format and runner written in pure C99 with zero dependencies. One `.fexe` file holds everything: metadata, multi-version code, per-OS run commands, feature variants, sandboxing rules, and optional integrity signatures — all in a human-readable TOML-inspired plaintext format.

---

## Build

```bash
# Linux / macOS / Termux
gcc -O2 -std=c99 -o fexe fexe.c

# Or with make
make
make install       # copies to /usr/local/bin/fexe

# Windows (MinGW)
gcc -O2 -std=c99 -o fexe.exe fexe.c
```

---

## Commands

| Command | Description |
|---|---|
| `fexe init <output.fexe>` | Interactive wizard to create a new package |
| `fexe run <file.fexe>` | Run the latest version of a package |
| `fexe run --remove <feat> --add <feat> <file>` | Run with features toggled |
| `fexe version <ver> <file.fexe>` | Run a specific version |
| `fexe install <url>` | Download, verify, and install from a URL |
| `fexe info <file.fexe>` | Show package metadata, versions, permissions |
| `fexe verify <file.fexe>` | Verify SHA256 integrity |
| `fexe hash <file.fexe>` | Print the SHA256 of a package file |
| `fexe list` | List all installed packages |

---

## The .fexe Format

A `.fexe` file is plain UTF-8 text. No brackets inside values, no binary blobs, no schemas — just sections and key-value pairs.

### Package metadata

```toml
[package]
name        = "myapp"
description = "Does something cool"
author      = "you"
license     = "MIT"
homepage    = "https://example.com"
created     = "2025-01-01"
updated     = "2025-06-01"
sandboxed   = true
```

### Sandboxing & permissions

Packages are sandboxed by default. Permissions are declared in the file and the user is prompted at runtime to allow or deny each one.

```toml
[permissions]
network    = false
filesystem = false
env        = false
process    = false
```

### Integrity

```toml
[integrity]
sha256 = "6c3bf577fbf042f883dbf080f49babc0b905699f940bc1c60efc9f6475bb5f7d"
pgp    = ""
```

Run `fexe hash myapp.fexe` to compute the hash, then paste it in. `fexe verify` will check it on every install.

### Versions

Each version has its own description, date, run commands per OS, and embedded source files.

```toml
[version.1.0.0]
description = "Initial release"
date        = "2025-01-01"

[run.all]
cmd = "python3 main.py"

[run.windows]
cmd = "python main.py"

[file.main.py]
print("Hello from fexe!")
```

Multiple versions live in the same file:

```toml
[version.1.1.0]
description = "Rewrite with multi-file support"
date        = "2025-06-01"

[run.all]
cmd = "python3 main.py --verbose"

[file.main.py]
from utils import greet
print(greet())

[file.utils.py]
def greet():
    return "Hello from fexe v1.1.0!"
```

Run a specific version:

```bash
fexe version 1.0.0 myapp.fexe
```

### Variants & features

Variants let you ship optional feature sets in the same file. Users can enable or disable features at run time with `--add` and `--remove`.

```toml
[variant.no-banner]

[feature.banner]
label   = "Show ASCII banner on startup"
enabled = false

[feature.telemetry]
label   = "Send usage stats"
enabled = false
```

```bash
fexe run --remove telemetry --add dark-mode myapp.fexe
```

### Supported OS keys for run commands

| Key | Platform |
|---|---|
| `all` | Any OS (fallback) |
| `linux` | Linux |
| `macos` | macOS |
| `windows` | Windows |
| `android` | Android / Termux |

---

## Full example

```toml
[package]
name        = "helloworld"
description = "Cross-platform hello world demo"
author      = "demo"
license     = "MIT"
sandboxed   = true

[permissions]
network    = false
filesystem = false

[integrity]
sha256 = ""
pgp    = ""

[version.1.0.0]
description = "Initial release"
date        = "2025-01-01"

[run.all]
cmd = "python3 main.py"

[run.windows]
cmd = "python main.py"

[file.main.py]
import sys, platform
name = sys.argv[1] if len(sys.argv) > 1 else "World"
print(f"Hello, {name}! [{platform.system()}]")

[variant.loud]

[feature.uppercase]
label   = "Print output in uppercase"
enabled = true
```

---

## How it works

When you run a `.fexe` file, fexe:

1. Parses the file and selects the target version
2. Extracts all embedded source files into a temp directory under `~/.fexe/`
3. Prompts the user to approve any requested permissions (if sandboxed)
4. Applies any variant/feature flags passed via `--add` / `--remove`
5. Runs the OS-appropriate command from inside the extracted directory
6. Nothing is installed system-wide unless you used `fexe install`

Installed packages live in `~/.fexe/` on Unix and `%APPDATA%\fexe\` on Windows.

---

## SHA256 implementation

fexe ships its own SHA256 implementation — no OpenSSL, no libcrypto. The same binary verifies integrity on every platform including Termux.

---

## License

MIT
