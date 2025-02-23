# ForceBindIP Version 2

A rewrite of ForceBindIP in C++ using MinHook library. This tool allows forcing applications to use specific network interfaces through IP binding.

## Features

- Supports both IPv6 and IPv4 binding
- Tested and working on x64 applications (IPv4)
- IPv6 functionality implemented but needs further testing

## Build Environment

- Built using Visual Studio 2022
- Requires MinHook library

## Usage

```powershell
injector.exe <ipv6_or_ipv4_address> <target_app_path>
```

### Example Output

```powershell
DLL injected successfully with preferred IP: <ipv6_or_ipv4_address>
```

## Status

- ✅ IPv4 binding fully tested on x64 applications
- ⏳ IPv6 binding needs additional testing
- ✅ MinHook integration complete

## Notes

Please report any issues or success stories through the issue tracker.
