# ForceBindIP Version 2

ForceBindIP Version 2 is a tool that allows you to force applications to use a specific network interface by binding their sockets to a particular IP address or by specifying an interface GUID. Built as a rewrite of the original ForceBindIP in C++ using the MinHook library, it is useful for testing network configurations, ensuring applications use a specific network path, or bypassing certain network restrictions.

## Features

- Bind applications to a specific IPv4 or IPv6 address.

- Bind applications to a network interface using its GUID, automatically selecting the appropriate IP address based on the socket family.

- Supports both TCP and UDP sockets.

- Verbose mode for detailed logging and debugging.

## Requirements

- Windows operating system with Winsock support.

- Compiled with Visual Studio 2022.

- Requires the MinHook library for hooking Winsock functions.

## Building the Project

1. Install Visual Studio 2022 with C++ development tools.

2. Clone or download the MinHook library and build it, or use prebuilt binaries.

3. Open the solution in Visual Studio, configure the include and library directories for MinHook, and build the project.

## Usage

Run the injector with the following syntax:

```cmd
injector.exe [options] <program> [args...]
```

### Options

- `-v`: Enable verbose mode for detailed logging.

- `-4 <IPv4>`: Bind to the specified IPv4 address (e.g., `192.168.1.1`).

- `-6 <IPv6>`: Bind to the specified IPv6 address (e.g., `fdfe:dcba:9876::1`).

- `-i <GUID>`: Bind to the network interface with the specified GUID (without curly braces, e.g., `11111111-2222-3333-4444-555555555555`).

### Notes on Binding

- **Direct IP Binding (`-4` or `-6`)**: The application’s sockets are bound to the specified IPv4 or IPv6 address.

- **Interface Binding (`-i`)**: The injector resolves the GUID to an IP address, prioritizing non-link-local IPv6 over IPv4. The DLL then binds sockets to this IP, but the application must support the corresponding address family (e.g., `AF_INET` for IPv4, `AF_INET6` for IPv6).

- The application must create sockets compatible with the specified or resolved IP’s address family for binding to succeed.

## Examples

- **Bind to a specific IPv4 address:**

```cmd
injector.exe -4 192.168.1.1 program.exe
```

Output:

```cmd
DLL injected successfully with IPv4: 192.168.1.1
```

- **Bind to a specific IPv6 address:**

```cmd
injector.exe -6 fdfe:dcba:9876::1 program.exe
```

Output:

```cmd
DLL injected successfully with IPv6: fdfe:dcba:9876::1
```

- **Bind to a network interface using its GUID:**

```cmd
injector.exe -i 11111111-2222-3333-4444-555555555555 program.exe
```

Output (example with resolved IP):

```cmd
DLL injected successfully with interface IP: IPv6:fdfe:dcba:9876::1
```

- **Verbose mode with interface binding:**

```cmd
injector.exe -v -i 11111111-2222-3333-4444-555555555555 program.exe
```

To find your network interface GUIDs and their associated IP addresses, you can:

- Use `ipconfig /all` in the command prompt.

- Build `guid.cpp` or run the provided `forcebindipguidfinder.exe` which lists active adapters.

## Known Issues

- When using IPv4 binding (`-4`), some applications like `curl` may encounter errors such as:

```cmd
curl: (6) getaddrinfo() thread failed to start
```

- If the application’s socket family (e.g., `AF_INET`) does not match the resolved IP’s family (e.g., IPv6 from `-i`), binding may fail silently, and the application will use the default interface.

Report additional issues through the issue tracker.

## Notes

- Ensure the specified IP address or interface is available and properly configured on your system.

- When using `-i`, provide the GUID without curly braces (e.g., `11111111-2222-3333-4444-555555555555`).

- The tool hooks Winsock functions (`socket`, `bind`, `connect`, `sendto`, `getsockname`) to enforce binding.

- Please report any issues or success stories through the issue tracker.

- This README was created by an AI.
