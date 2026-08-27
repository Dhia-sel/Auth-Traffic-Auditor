# auth-traffic-auditor

Outil modulaire pour tester des mécanismes d'authentification et des mauvaises pratiques réseau (usage lab/éducatif uniquement).

Quickstart
---------

1. Installer les dépendances :

```bash
python -m pip install -r requirements.txt
```

2. Lancer le serveur de test local (lab) :

```bash
python lab/dummy_login_server.py
```

3. Lister les modules disponibles :

```bash
python -m auth_traffic_auditor.cli --list
```

4. Exécuter un module (exemple `password_spraying`) :

```bash
python -m auth_traffic_auditor.cli password_spraying http://127.0.0.1:5000
```

5. Pour les modules dangereux (ARP/DNS/sniffing), ajouter `--confirm-lab` pour confirmer que vous êtes en environnement de laboratoire :

```bash
python -m auth_traffic_auditor.cli arp_mitm 192.168.1.10 --confirm-lab gateway_ip=192.168.1.1
```

Usage général
-------------

- Les arguments supplémentaires peuvent être passés sous la forme `cle=valeur` et seront transmis au module.
- Pour les listes, séparez les valeurs par des virgules (ex: `usernames=admin,test`).

Safety
------
N'exécutez jamais les modules qui forgent ou interceptent du trafic sur des réseaux que vous ne possédez pas ou contrôlez explicitement. Respectez la loi et l'éthique.
