#!/usr/bin/env python3
"""
Generate export/import reports for a PE DLL and scaffold a proxy DLL that forwards
all exports to a renamed original (e.g., astra_.dll).

Outputs:
- reports/<dll>_exports.csv and .md
- reports/<dll>_imports.csv and .md
- proxy/
  - proxy.def (forwarders)
  - proxy.c (minimal DllMain)
  - CMakeLists.txt (for MSVC/MinGW)
  - README.md (usage/build instructions)

Usage:
  python tools/pe_proxy_gen.py /path/to/astra.dll --proxy-name astra --forward-to astra_
"""

import argparse
import csv
import os
import sys
from pathlib import Path

try:
    import pefile
except Exception as exc:  # pragma: no cover
    print("[ERROR] Missing dependency 'pefile'. Install with: pip install pefile", file=sys.stderr)
    raise


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def decode_bytes(value: bytes | None) -> str | None:
    if value is None:
        return None
    try:
        return value.decode("utf-8", errors="ignore")
    except Exception:
        try:
            return value.decode("latin-1", errors="ignore")
        except Exception:
            return None


def format_markdown_table(headers: list[str], rows: list[list[str]]) -> str:
    md_lines = []
    md_lines.append("| " + " | ".join(headers) + " |")
    md_lines.append("| " + " | ".join(["---"] * len(headers)) + " |")
    for row in rows:
        md_lines.append("| " + " | ".join(row) + " |")
    return "\n".join(md_lines) + "\n"


def write_csv(path: Path, headers: list[str], rows: list[list[str]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerows(rows)


def write_text(path: Path, content: str) -> None:
    with path.open("w", encoding="utf-8") as f:
        f.write(content)


def generate_export_reports(pe: pefile.PE, dll_basename: str, reports_dir: Path) -> list[dict]:
    export_rows_csv: list[list[str]] = []
    export_rows_md: list[list[str]] = []
    exports: list[dict] = []

    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT") and pe.DIRECTORY_ENTRY_EXPORT is not None:
        for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            name = decode_bytes(sym.name)
            ordinal = str(sym.ordinal) if getattr(sym, "ordinal", None) is not None else ""
            forwarder = decode_bytes(getattr(sym, "forwarder", None)) or ""
            addr = hex(sym.address) if getattr(sym, "address", None) is not None else ""

            row = [name or "", ordinal, forwarder, addr]
            export_rows_csv.append(row)
            export_rows_md.append([
                name or "",
                ordinal,
                forwarder or "",
                addr,
            ])
            exports.append({
                "name": name,
                "ordinal": int(ordinal) if ordinal else None,
                "forwarder": forwarder or None,
            })

    headers = ["Name", "Ordinal", "Forwarder", "RVA/Addr"]
    ensure_dir(reports_dir)
    write_csv(reports_dir / f"{dll_basename}_exports.csv", headers, export_rows_csv)
    write_text(reports_dir / f"{dll_basename}_exports.md", format_markdown_table(headers, export_rows_md))
    return exports


def generate_import_reports(pe: pefile.PE, dll_basename: str, reports_dir: Path) -> None:
    import_rows_csv: list[list[str]] = []
    import_rows_md: list[list[str]] = []

    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT") and pe.DIRECTORY_ENTRY_IMPORT is not None:
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = decode_bytes(entry.dll) or ""
            for imp in entry.imports:
                name = decode_bytes(imp.name) or ""
                ordinal = str(imp.ordinal) if getattr(imp, "ordinal", None) is not None else ""
                hint = str(getattr(imp, "hint", ""))
                import_rows_csv.append([dll, name, ordinal, hint])
                import_rows_md.append([dll, name, ordinal, hint])

    headers = ["DLL", "Name", "Ordinal", "Hint"]
    ensure_dir(reports_dir)
    write_csv(reports_dir / f"{dll_basename}_imports.csv", headers, import_rows_csv)
    write_text(reports_dir / f"{dll_basename}_imports.md", format_markdown_table(headers, import_rows_md))


def build_forwarder_def(exports: list[dict], proxy_name: str, forward_to: str) -> str:
    lines: list[str] = []
    lines.append("LIBRARY \"%s\"" % proxy_name)
    lines.append("EXPORTS")
    for exp in exports:
        name = exp.get("name")
        ordinal = exp.get("ordinal")
        # Forwarder target: omit .dll per def syntax convention (e.g., KERNEL32.CreateFileW)
        if name:
            if ordinal is not None:
                lines.append(f"    {name}={forward_to}.{name} @{ordinal}")
            else:
                lines.append(f"    {name}={forward_to}.{name}")
        else:
            # Export by ordinal only; forward by ordinal using # syntax
            if ordinal is not None:
                lines.append(f"    @{ordinal}={forward_to}.#{ordinal}")
            # If neither name nor ordinal present, skip (should not happen)
    lines.append("")
    return "\n".join(lines)


def generate_proxy_project(exports: list[dict], proxy_name: str, forward_to: str, proxy_dir: Path) -> None:
    ensure_dir(proxy_dir)
    def_path = proxy_dir / "proxy.def"
    c_path = proxy_dir / "proxy.c"
    cmake_path = proxy_dir / "CMakeLists.txt"
    readme_path = proxy_dir / "README.md"

    write_text(def_path, build_forwarder_def(exports, proxy_name=proxy_name, forward_to=forward_to))

    proxy_c = (
        "#ifdef _WIN32\n"
        "#  include <windows.h>\n"
        "BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {\n"
        "    (void)hModule; (void)ul_reason_for_call; (void)lpReserved;\n"
        "    return TRUE;\n"
        "}\n"
        "#else\n"
        "int main(void) { return 0; }\n"
        "#endif\n"
    )
    write_text(c_path, proxy_c)

    cmake_txt = (
        f"cmake_minimum_required(VERSION 3.15)\n"
        f"project({proxy_name}_proxy C)\n"
        f"\n"
        f"add_library({proxy_name} SHARED proxy.c)\n"
        f"# Use module definition file for exports/forwarders\n"
        f"set_target_properties({proxy_name} PROPERTIES LINK_FLAGS \"/DEF:proxy.def\")\n"
        f"\n"
        f"if(MINGW)\n"
        f"  # With MinGW, also pass the def file to the linker explicitly\n"
        f"  target_link_options({proxy_name} PRIVATE \"-Wl,proxy.def\")\n"
        f"endif()\n"
    )
    write_text(cmake_path, cmake_txt)

    readme = (
        f"# {proxy_name}.dll proxy\n\n"
        f"This proxy DLL forwards all exports to `{forward_to}.dll`.\n\n"
        f"Steps to use:\n"
        f"1. Rename the original `{proxy_name}.dll` to `{forward_to}.dll`.\n"
        f"2. Build this project to produce a new `{proxy_name}.dll`.\n"
        f"3. Place the new `{proxy_name}.dll` next to `{forward_to}.dll`.\n\n"
        f"Build (Windows MSVC):\n\n"
        f"- Open a Developer Command Prompt for VS.\n"
        f"- Run:\n"
        f"  mkdir build && cd build\n"
        f"  cmake -G \"Visual Studio 17 2022\" ..\n"
        f"  cmake --build . --config Release\n\n"
        f"Build (MinGW on Windows):\n\n"
        f"- Ensure `mingw-w64` is installed.\n"
        f"- Run:\n"
        f"  mkdir build && cd build\n"
        f"  cmake -G \"MinGW Makefiles\" ..\n"
        f"  cmake --build . --config Release\n\n"
        f"Notes:\n"
        f"- The `proxy.def` file contains forwarders (e.g., `Func=astra_.Func`).\n"
        f"- For ordinal-only exports, the forwarder uses `@N=astra_.#N`.\n"
    )
    write_text(readme_path, readme)


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate export/import reports and a proxy forwarding DLL project.")
    parser.add_argument("dll_path", type=str, help="Path to the original DLL (e.g., astra.dll)")
    parser.add_argument("--proxy-name", type=str, default=None, help="Name of the proxy DLL to build (base name without .dll). Defaults to DLL base name.")
    parser.add_argument("--forward-to", type=str, default=None, help="Target base name to forward to (without .dll). Defaults to <proxy-name>_.")
    parser.add_argument("--out-dir", type=str, default=".", help="Root output directory for reports and proxy folder.")
    args = parser.parse_args()

    dll_path = Path(args.dll_path).resolve()
    if not dll_path.exists():
        print(f"[ERROR] DLL not found: {dll_path}", file=sys.stderr)
        return 2

    dll_basename = dll_path.stem
    proxy_name = args.proxy_name or dll_basename
    forward_to = args.forward_to or (proxy_name + "_")

    out_root = Path(args.out_dir).resolve()
    reports_dir = out_root / "reports"
    proxy_dir = out_root / "proxy"

    pe = pefile.PE(str(dll_path))

    exports = generate_export_reports(pe, dll_basename=dll_basename, reports_dir=reports_dir)
    generate_import_reports(pe, dll_basename=dll_basename, reports_dir=reports_dir)
    generate_proxy_project(exports, proxy_name=proxy_name, forward_to=forward_to, proxy_dir=proxy_dir)

    print(f"[OK] Reports written to: {reports_dir}")
    print(f"[OK] Proxy project written to: {proxy_dir}")
    print(f"[INFO] Forwarding target: {forward_to}.dll")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

