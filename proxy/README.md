# astra.dll proxy with logging

This proxy DLL forwards exports to `astra_.dll` and logs all network requests and responses made by the original DLL via Winsock (`send`, `recv`, `connect`). Logs are written to `log.txt` in the same folder as the DLL.

Usage:

1. Rename the original `astra.dll` to `astra_.dll`.
2. Build this project to produce the new `astra.dll`.
3. Place the new `astra.dll` next to `astra_.dll`.
4. Run your application; `log.txt` will be created beside the DLL.

Build (Windows MSVC):

- Developer Command Prompt for VS:
  - `mkdir build && cd build`
  - `cmake -G "Visual Studio 17 2022" ..`
  - `cmake --build . --config Release`

Build (MinGW on Windows):

- Ensure `mingw-w64` is installed
  - `mkdir build && cd build`
  - `cmake -G "MinGW Makefiles" ..`
  - `cmake --build . --config Release`

Notes:
- Export forwarding is handled by `proxy.def` (e.g., `Func=astra_.Func`).
- Logging hooks `send`/`recv`/`connect` in the IAT of `astra_.dll`; other modules are untouched.
- If payloads are large, dumps are truncated to 64KB per call.
