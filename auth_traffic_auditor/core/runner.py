from .registry import get_module
from ..detection.analyzer import analyze
from ..mappings.iso27001 import describe_controls

def run_attack(module_name: str, target: str, **kwargs) -> None:
    module_cls = get_module(module_name)
    module = module_cls()
    print(f"[Core] Lancement de '{module.name}' contre {target}")
    result = module.run(target, **kwargs)
    finding = analyze(result)
    controls = describe_controls(module.iso_controls)
    print(f"\n=== Rapport — {result.module_name} ===")
    print(f"Statut         : {'SUCCÈS' if result.success else 'ÉCHEC'}")
    print(f"Résumé         : {result.summary}")
    print(f"Sévérité       : {finding.severity}")
    print(f"Recommandation : {finding.recommendation}")
    print("Contrôles ISO 27001 concernés :")
    for ref, desc in controls.items():
        print(f"  - {ref} : {desc}")