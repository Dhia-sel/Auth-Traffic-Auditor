
from __future__ import annotations
import argparse
import importlib
import inspect
import pkgutil
from typing import Any

from .core.registry import available_modules, get_module
from .core.runner import run_attack


def _discover_attack_modules() -> None:
    """Import all submodules under `auth_traffic_auditor.attacks` so they register."""
    try:
        import auth_traffic_auditor.attacks as attacks_pkg
    except Exception:
        return
    for _, name, _ in pkgutil.iter_modules(attacks_pkg.__path__, attacks_pkg.__name__ + "."):
        try:
            importlib.import_module(name)
        except Exception as exc:
            print(f"Avertissement : impossible de charger '{name}' ({exc})")
            continue


def _parse_kv_pairs(pairs: list[str]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for item in pairs:
        if "=" not in item:
            continue
        key, val = item.split("=", 1)
        val = val.strip()
        if "," in val:
            out[key] = [v.strip() for v in val.split(",") if v.strip()]
            continue
        if val.lower() in ("true", "false"):
            out[key] = val.lower() == "true"
            continue
        try:
            out[key] = int(val)
            continue
        except ValueError:
            pass
        try:
            out[key] = float(val)
            continue
        except ValueError:
            pass
        out[key] = val
    return out


def main(argv: list[str] | None = None) -> None:
    _discover_attack_modules()
    modules = available_modules()

    parser = argparse.ArgumentParser(prog="ata")
    parser.add_argument("-t", "--target", help="Cible (URL ou host selon le module)")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-m", "--module", help="Nom du module (voir --list)")
    group.add_argument("-n", "--number", type=int, help="Numéro du module (voir --list)")
    parser.add_argument("--info", metavar="MODULE", help="Afficher les paramètres/support du module (introspection)")
    parser.add_argument("--list", action="store_true", help="Lister les modules disponibles")
    parser.add_argument("--confirm-lab", action="store_true", help="Confirmer un module dangereux")
    # parse_known_args plutôt que REMAINDER : les key=value peuvent être
    # écrits avant OU après --confirm-lab sans que l'un avale l'autre.
    args, remaining = parser.parse_known_args(argv)

    if args.list:
        print("Modules disponibles :")
        for i, m in enumerate(modules, start=1):
            print(f"  {i}. {m}")
        return

    if args.info:
        try:
            module_cls = get_module(args.info)
        except KeyError as exc:
            print(f"Erreur : {exc}")
            return
        run_fn = getattr(module_cls, "run", None)
        if run_fn is None:
            print(f"Module '{args.info}' n'a pas de méthode run()")
            return
        sig = inspect.signature(run_fn)
        # drop 'self' from parameters
        params = [p for p in sig.parameters.values() if p.name != "self"]
        print(f"Module: {args.info}")
        print(f"Signature: run({', '.join(str(p) for p in params)})")
        doc = inspect.getdoc(run_fn) or inspect.getdoc(module_cls) or "(pas de doc)"
        print("Doc:\n" + doc)
        return

    if not args.target or (args.module is None and args.number is None):
        parser.print_help()
        return

    if args.number is not None:
        if not (1 <= args.number <= len(modules)):
            print(f"Numéro invalide. Utilisez --list (1-{len(modules)}).")
            return
        module_name = modules[args.number - 1]
    else:
        module_name = args.module

    try:
        module_cls = get_module(module_name)
    except KeyError as exc:
        print(f"Erreur : {exc}")
        return

    if module_cls.requires_confirmation and not args.confirm_lab:
        print(f"Module '{module_name}' est dangereux et nécessite --confirm-lab (usage lab only).")
        return

    extras = _parse_kv_pairs(remaining)
    try:
        run_attack(module_name, args.target, **extras)
    except ValueError as exc:
        print(f"Erreur : {exc}")


if __name__ == "__main__":
    main()