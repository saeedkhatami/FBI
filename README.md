# Version 2

The development branch incorporates architectural enhancements for the FBI software, including:

- Support for both x64 and x86 applications ✓
- IPv6 support (Logically implemented) ✓
- Kill switch mechanism
  - Implementation based on IP connectivity
  - Two fallback options:
    - Switch to alternate IP
    - Fallback to 0.0.0.0 (No Connection)
  - Status: Pending connection retry timing logic
- Delayed injection capabilities
  - Status: In Progress
  - Known issues:
    - Application suspension causes race conditions
    - IP priority conflicts with Windows settings
- Redesigned graphical user interface
  - Status: Pending
