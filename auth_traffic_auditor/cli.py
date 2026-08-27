"""CLI for auth-traffic-auditor.

Features:
- auto-import all modules in the `attacks` package so they register
- simple argument parsing: `auth-traffic-auditor <module> <target> [key=value ...]`
- list available modules with `--list`
"""
from __future__ import annotations

import argparse
import importlib
import pkgutil
from typing import Any

from .core.registry import available_modules
from .core.runner import run_attack


def _discover_attack_modules() -> None:
    """Import all submodules under `auth_traffic_auditor.attacks` so they register."""
    try:
        import auth_traffic_auditor.attacks as attacks_pkg
    except Exception:
        return
    for finder, name, ispkg in pkgutil.iter_modules(attacks_pkg.__path__, attacks_pkg.__name__ + "."):
        try:
            importlib.import_module(name)
        except Exception:
            # skip modules that fail to import; registry will simply not include them
            continue


def _parse_kv_pairs(pairs: list[str]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for item in pairs:
        if "=" not in item:
            continue
        key, val = item.split("=", 1)
        val = val.strip()
        # lists via comma
        if "," in val:
            items = [v.strip() for v in val.split(",") if v.strip()]
            out[key] = items
            continue
        # booleans
        if val.lower() in ("true", "false"):
            out[key] = val.lower() == "true"
            continue
        # numbers
        try:
            out[key] = int(val)
            continue
        except Exception:
            pass
        try:
            out[key] = float(val)
            continue
        except Exception:
            pass
        out[key] = val
    return out


def main(argv: list[str] | None = None) -> None:
    _discover_attack_modules()

    parser = argparse.ArgumentParser(prog="auth-traffic-auditor")
    parser.add_argument("module", nargs="?", help="Module to run (or use --list)")
    parser.add_argument("target", nargs="?", help="Target for the module (URL or host)")
    parser.add_argument("extras", nargs=argparse.REMAINDER, help="Extra key=value args passed to module")
    parser.add_argument("--list", action="store_true", help="List available modules and exit")
    parser.add_argument("--confirm-lab", action="store_true", help="Confirm running lab-only risky modules")
    args = parser.parse_args(argv)

    if args.list:
        print("Modules disponibles :")
        for m in available_modules():
            print(f" - {m}")
        return

    if not args.module or not args.target:
        parser.print_help()
        return

    dangerous = {"arp_mitm", "sniffing", "dns_spoofing"}
    if args.module in dangerous and not args.confirm_lab:
        print(
            f"Module '{args.module}' est dangereux et nécessite --confirm-lab pour exécution (usage lab only)."
        )
        return

    extras = _parse_kv_pairs(args.extras or [])
    run_attack(args.module, args.target, **extras)


if __name__ == "__main__":
    main()