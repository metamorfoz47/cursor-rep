# astra.dll proxy

This proxy DLL forwards all exports to `astra_.dll`.

Steps to use:
1. Rename the original `astra.dll` to `astra_.dll`.
2. Build this project to produce a new `astra.dll`.
3. Place the new `astra.dll` next to `astra_.dll`.

Build (Windows MSVC):

- Open a Developer Command Prompt for VS.
- Run:
  mkdir build && cd build
  cmake -G "Visual Studio 17 2022" ..
  cmake --build . --config Release

Build (MinGW on Windows):

- Ensure `mingw-w64` is installed.
- Run:
  mkdir build && cd build
  cmake -G "MinGW Makefiles" ..
  cmake --build . --config Release

Notes:
- The `proxy.def` file contains forwarders (e.g., `Func=astra_.Func`).
- For ordinal-only exports, the forwarder uses `@N=astra_.#N`.
