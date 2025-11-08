# SharpUp - Rust Port

This is an in-progress Rust port of the C# SharpUp privilege escalation enumeration tool.

## Current Status

**Functional:** ✅ Core tool works end-to-end
**Checks Implemented:** 4/15 (27%)
**Platform:** Windows (x86_64-pc-windows-msvc) + Linux stubs for development

### Implemented Checks

1. ✅ **AlwaysInstallElevated** - MSI installer policy misconfiguration
2. ✅ **TokenPrivileges** - Abusable token privileges (SeDebug, SeImpersonate, etc.)
3. ✅ **RegistryAutoLogons** - Plaintext autologon credentials in registry
4. ✅ **UnattendedInstallFiles** - Sysprep/unattend files with potential credentials

### In Progress

- File utilities module (ACL checking, GPP decryption)
- Remaining 11 vulnerability checks

## Build Instructions

### Requirements

- Rust 1.70+ (2021 edition)
- Windows SDK (for Windows builds)
- Linux/macOS for cross-platform development (stubs compile but checks require Windows)

### Build

```bash
# Development build
cargo build

# Release build (optimized, stripped)
cargo build --release

# Run tests
cargo test

# Run all checks
cargo run

# Run specific check
cargo run -- TokenPrivileges

# Audit mode (run even if admin)
cargo run -- --audit
```

### Cross-compilation for Windows

```bash
# From Linux/macOS
rustup target add x86_64-pc-windows-msvc
cargo build --target x86_64-pc-windows-msvc --release
```

## Usage

```
SharpUp [OPTIONS] [CHECKS]...

Options:
  --audit       Enable audit mode (run checks even if already admin)
  -v, --verbose Enable verbose logging
  -h, --help    Print help

Examples:
  sharpup                          # Run all checks
  sharpup --audit                  # Run all checks (audit mode)
  sharpup TokenPrivileges          # Run single check
  sharpup AlwaysInstallElevated TokenPrivileges  # Run multiple checks
```

## Architecture

### Modules

- `src/main.rs` - CLI entry point and orchestration
- `src/lib.rs` - Library exports
- `src/error.rs` - Error type hierarchy
- `src/checks/` - Vulnerability check implementations
  - `mod.rs` - VulnerabilityCheck trait
  - `always_install_elevated.rs`
  - `token_privileges.rs`
  - `registry_autologons.rs`
  - `unattended_install_files.rs`
- `src/native/` - Win32 FFI wrappers
  - `win32.rs` - Safe RAII wrappers for Windows APIs
- `src/utils/` - Utility modules
  - `registry.rs` - Registry access
  - `identity.rs` - Token/privilege checks

### Design Decisions

**No Runtime Reflection:**
Instead of C#'s `Assembly.GetTypes()`, we use a compile-time check registry in `main.rs`. This is safer, faster, and more idiomatic in Rust.

**Result-based Error Handling:**
All operations return `Result<T, E>` instead of exceptions. Silent failures from C# (`catch { }`) are replaced with explicit error handling.

**RAII for Resource Safety:**
Windows HANDLEs are wrapped in RAII types (`SafeHandle`, `RegKey`) that automatically close on drop, preventing resource leaks.

**Cross-platform Stubs:**
Registry/identity utilities have stub implementations for non-Windows platforms, allowing development and compilation on Linux/macOS.

## Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `windows` | 0.52 | Safe Win32 API bindings |
| `clap` | 4.4 | CLI argument parsing |
| `thiserror` | 1.0 | Error type derives |
| `anyhow` | 1.0 | Application error handling |
| `tracing` | 0.1 | Structured logging |

All dependencies are actively maintained with no known CVEs.

## Safety

**Unsafe Code Usage:**
Unsafe blocks are isolated to Win32 FFI calls in `src/native/win32.rs`. All unsafe code is:
- Bounded and validated
- Wrapped in safe public APIs
- Documented with safety justification
- Protected by RAII wrappers to prevent leaks

**Memory Safety:**
Rust's borrow checker and type system prevent:
- Buffer overflows
- Use-after-free
- Double-free
- Data races
- Null pointer dereferences

## Development Roadmap

### Phase 1: Core Infrastructure ✅
- [x] Project setup
- [x] Error types
- [x] VulnerabilityCheck trait
- [x] Win32 FFI layer
- [x] Registry utilities
- [x] Identity utilities
- [x] Main orchestration

### Phase 2: Simple Checks ✅ (4/15)
- [x] AlwaysInstallElevated
- [x] TokenPrivileges
- [x] RegistryAutoLogons
- [x] UnattendedInstallFiles

### Phase 3: File Utilities 🚧 (In Progress)
- [ ] ACL permission checking
- [ ] GPP password decryption
- [ ] XML parsing
- [ ] Recursive file search

### Phase 4: Remaining Checks (11/15)
- [ ] CachedGPPPassword
- [ ] DomainGPPPassword
- [ ] HijackablePaths
- [ ] RegistryAutoruns
- [ ] ModifiableServiceBinaries
- [ ] ModifiableServices
- [ ] ModifiableServiceRegistryKeys
- [ ] UnquotedServicePath
- [ ] ModifiableScheduledTaskFile
- [ ] ProcessDLLHijack
- [ ] McAfeeSitelistFiles

### Phase 5: Polish
- [ ] Add `rayon` for true parallelism
- [ ] CI configuration
- [ ] Integration tests
- [ ] Performance optimization

## License

BSD 3-Clause (matching original SharpUp)

## Acknowledgments

This is a port of the original C# [SharpUp](https://github.com/GhostPack/SharpUp) by [@harmj0y](https://twitter.com/harmj0y).

Rust port: Developed as a learning exercise and to demonstrate safe systems programming practices.

**Intended for authorized penetration testing and security research only.**
