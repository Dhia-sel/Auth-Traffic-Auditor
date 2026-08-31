# Auth & Traffic Auditor

Outil modulaire d'audit de sécurité, ciblant l'authentification et le
trafic réseau, avec mapping systématique vers les contrôles **ISO
27001**. Chaque technique offensive est un plugin indépendant ; chaque
résultat est automatiquement relié à une sévérité, une recommandation,
et un ou plusieurs contrôles ISO.



## Sommaire

- [Architecture](#architecture)
- [Modules d'attaque](#modules-dattaque)
- [Installation](#installation)
- [Utilisation](#utilisation)
- [Le CLI en détail](#le-cli-en-détail)
- [Sécurité : modules "dangereux"](#sécurité--modules-dangereux)
- [Tester le projet](#tester-le-projet)
- [Structure des fichiers](#structure-des-fichiers)

---

## Architecture

```
core/         interface commune (AttackModule, AttackResult), registre,
              orchestrateur, validation HTTP partagée
attacks/      un module = une technique d'attaque (plugin autonome)
detection/    analyse standardisée d'un résultat -> Finding (sévérité, recommandation)
mappings/     correspondance module -> contrôle ISO 27001
lab/          cible factice et volontairement vulnérable, pour tester en local
tests/        script de vérification des 6 modules
cli.py        point d'entrée en ligne de commande
```

Chaque module d'attaque hérite de `AttackModule` (dans
`core/plugin_base.py`) et s'enregistre automatiquement via le
décorateur `@register`. Le CLI découvre tous les modules présents dans
`attacks/` sans avoir besoin de les connaître à l'avance — ajouter un
7ᵉ module ne demande de modifier aucun fichier existant.

## Modules d'attaque

| # | Module | Contrôle ISO | Nécessite root | Description |
|---|--------|:---:|:---:|---|
| 1 | `arp_mitm` | A.13 | oui | Empoisonnement ARP entre une victime et une passerelle |
| 2 | `bruteforce` | A.9 | non | Teste une wordlist de mots de passe sur UN compte |
| 3 | `dns_spoofing` | A.13 | oui | Répond de façon falsifiée à des requêtes DNS ciblées |
| 4 | `password_spraying` | A.9 | non | Teste UN mot de passe sur PLUSIEURS comptes |
| 5 | `service_scan` | A.12 | non | Scan de ports TCP + récupération de bannières |
| 6 | `sniffing` | A.13 | oui | Capture passive et extraction d'identifiants en clair |

Les modules marqués **root** manipulent des paquets bas niveau (ARP,
DNS brut, capture réseau) et nécessitent un vrai réseau local pour être
utiles — ils sont bloqués par défaut derrière `--confirm-lab` (voir plus bas).

## Installation

```bash
git clone https://github.com/Dhia-sel/Auth-Traffic-Auditor.git
cd Auth-Traffic-Auditor
python3 -m venv .venv
source .venv/bin/activate          # sous Windows : .venv\Scripts\activate
pip install -e ".[lab,dev]"
```

- `.[lab]` installe Flask, nécessaire uniquement pour la cible de test `lab/dummy_login_server.py`
- `.[dev]` installe les outils de développement (pytest, etc.)
- `pip install -e .` génère la commande **`ata`**, disponible ensuite partout dans le terminal

Vérifiez l'installation :
```bash
ata --list
```
```
Modules disponibles :
  1. arp_mitm
  2. bruteforce
  3. dns_spoofing
  4. password_spraying
  5. service_scan
  6. sniffing
```

## Utilisation

### 1. Démarrer la cible de test (dans un premier terminal)

```bash
python lab/dummy_login_server.py
```
Sert un faux formulaire de connexion sur `http://127.0.0.1:5000`
(identifiants valides : `admin` / `azerty`), volontairement sans
rate-limiting — c'est le but, pour que `bruteforce` et
`password_spraying` aient quelque chose à démontrer.

### 2. Lancer un module (dans un second terminal)

Deux façons de désigner le module — par numéro ou par nom :

```bash
ata -t http://127.0.0.1:5000 -n 2
ata -t http://127.0.0.1:5000 -m bruteforce
```

### 3. Lire le rapport

```
[Core] Lancement de 'bruteforce' contre http://127.0.0.1:5000

=== Rapport — bruteforce ===
Statut         : SUCCÈS
Résumé         : Mot de passe trouvé pour 'admin' en 587 tentative(s), sans blocage détecté.
Sévérité       : Élevée
Recommandation : Faiblesse confirmée : voir les contrôles ISO 27001 associés pour la remédiation attendue.
Contrôles ISO 27001 concernés :
  - A.9 : Contrôle d'accès — gestion des accès utilisateurs et authentification
```

## Le CLI en détail

```bash
ata --list                                       # liste numérotée des modules
ata -t <cible> -n <numéro>                       # lance un module par numéro
ata -t <cible> -m <nom_module>                   # lance un module par nom
ata -t <cible> -n <numéro> cle=valeur cle2=valeur2  # passe des paramètres au module
ata -t <cible> -n <numéro> --confirm-lab         # requis pour les modules dangereux
```

Les paramètres `cle=valeur` sont convertis automatiquement selon leur
forme :
- `true` / `false` → booléen
- des nombres → `int` ou `float`
- une liste séparée par des virgules (`a,b,c`) → liste de chaînes
- sinon → chaîne de caractères telle quelle

**Exemples concrets** :

```bash
# bruteforce avec un nom d'utilisateur différent
ata -t http://127.0.0.1:5000 -n 2 username=root

# password spraying avec une liste de comptes personnalisée
ata -t http://127.0.0.1:5000 -n 4 usernames=admin,root,guest passwords=azerty,Password123

# scan de services sur des ports spécifiques
ata -t 127.0.0.1 -n 5 ports=22,80,443,5000

# ARP MITM (module dangereux, nécessite --confirm-lab et root)
sudo $(which ata) -t 192.168.1.50 -n 1 gateway_ip=192.168.1.1 duration=30 --confirm-lab
```

> L'ordre entre `--confirm-lab` et les `cle=valeur` n'a pas
> d'importance, les deux formes ci-dessus sont équivalentes.

## Sécurité : modules "dangereux"

`arp_mitm`, `dns_spoofing` et `sniffing` manipulent le réseau à un
niveau qui peut perturber d'autres machines (caches ARP corrompus,
résolutions DNS faussées) — ils sont donc bloqués par défaut :

```bash
$ ata -t 192.168.1.50 -n 1 gateway_ip=192.168.1.1
Module 'arp_mitm' est dangereux et nécessite --confirm-lab (usage lab only).
```

Chaque module dangereux se déclare lui-même via l'attribut
`requires_confirmation = True` dans sa classe (`core/plugin_base.py`
définit `False` par défaut) — le CLI n'a besoin de connaître aucune
liste de noms, un futur module dangereux s'auto-protège simplement en
déclarant cet attribut.

Ces 3 modules nécessitent en plus des **privilèges root/administrateur**
(accès raw socket) — sans ça, ils échouent proprement avec un message
clair plutôt qu'une erreur Python brute.

## Tester le projet

```bash
python tests/run_all_tests.py
```

Lance automatiquement la cible de lab, teste les 3 modules HTTP
(`bruteforce`, `password_spraying`, `service_scan`) en conditions
réelles, et vérifie l'enregistrement + la validation des paramètres des
3 modules réseau bas niveau (qui nécessitent un vrai LAN + root pour un
test complet, impossible à automatiser sans matériel réel). Code de
sortie `0` si tout passe, `1` sinon — utilisable dans une CI.

## Structure des fichiers

```
auth_traffic_auditor/
├── __init__.py
├── cli.py
├── core/
│   ├── plugin_base.py      # AttackModule (classe de base), AttackResult
│   ├── registry.py         # enregistrement/découverte des modules
│   ├── runner.py           # orchestration : run + analyse + mapping ISO
│   └── http_utils.py       # validation partagée des réponses HTTP de login
├── attacks/
│   ├── bruteforce.py
│   ├── password_spraying.py
│   ├── arp_mitm.py
│   ├── dns_spoofing.py
│   ├── service_scan.py
│   ├── sniffing.py
│   └── wordlists/
│       └── common-passwords.txt   # SecLists, 10 000 mots de passe
├── detection/
│   └── analyzer.py         # AttackResult -> Finding (sévérité, recommandation)
└── mappings/
    └── iso27001.py         # description des contrôles ISO 27001

lab/
└── dummy_login_server.py   # cible de test volontairement vulnérable
|
tests/
└── run_all_tests.py        # vérifie les 6 modules
|
pyproject.toml               # packaging + commande CLI `ata`
requirements.txt
```