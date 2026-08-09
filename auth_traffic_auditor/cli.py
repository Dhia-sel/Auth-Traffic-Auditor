import sys
from .attacks import arp_mitm
from .attacks import bruteforce
from .attacks import dns_spoofing
from .attacks import password_spraying
from .attacks import service_scan
from .attacks import sniffing
from .core.registry import available_modules
from .core.runner import run_attack

def main() -> None:
    if len(sys.argv) < 3:
        print("Usage : auth-traffic-auditor <module> <target>")
        print(f"Modules disponibles : {', '.join(available_modules())}")
        sys.exit(1)
    module_name, target = sys.argv[1], sys.argv[2]
    run_attack(module_name, target)

if __name__ == "__main__":
    main()