#!/usr/bin/env python3
"""Enable GhidraMCP in the user's CodeBrowser tool configuration."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys


PLUGIN_CLASS = "com.downIoads.GhidraMCPPlugin"
EXTENSION_BLOCK = (
    '            <EXTENSION NAME="GhidraMCP">\n'
    f'                <PLUGIN CLASS="{PLUGIN_CLASS}" />\n'
    "            </EXTENSION>\n"
)


def enable_plugin(tool_config: Path) -> bool:
    text = tool_config.read_text(encoding="utf-8")
    if f'PLUGIN CLASS="{PLUGIN_CLASS}"' in text:
        return False

    if "</EXTENSIONS>" in text:
        updated = text.replace("        </EXTENSIONS>", EXTENSION_BLOCK + "        </EXTENSIONS>", 1)
    elif "</TOOL>" in text:
        extensions = "        <EXTENSIONS>\n" + EXTENSION_BLOCK + "        </EXTENSIONS>\n"
        updated = text.replace("    </TOOL>", extensions + "    </TOOL>", 1)
    else:
        raise ValueError(f"unrecognized Ghidra tool configuration: {tool_config}")

    tool_config.write_text(updated, encoding="utf-8")
    return True


def find_tool_configs(config_home: Path, version: str) -> list[Path]:
    ghidra_home = config_home / "ghidra"
    candidates = sorted(ghidra_home.glob(f"{version}*/tools/_code_browser.tcd"))
    return [path for path in candidates if path.is_file()]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config-home", type=Path, default=Path.home() / ".config")
    parser.add_argument("--version", default="ghidra_12.2")
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args()

    configs = find_tool_configs(args.config_home, args.version)
    if not configs:
        message = "CodeBrowser configuration not found; run Ghidra once to create it"
        print(message, file=sys.stderr)
        return 1 if args.strict else 0

    for config in configs:
        changed = enable_plugin(config)
        print(f"{'enabled' if changed else 'already enabled'}: {config}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
