# CyberGuard System-Wide Defense Agent

## Description (FR & EN)
**FR :** Agent d'interception réseau système pour Windows. Il garantit qu'aucun trafic malveillant, pornographique ou de jeu d'argent ne passe à travers les mailles du filet, **même si l'utilisateur désactive ou n'installe pas l'extension de navigateur**.

**EN:** Windows system-wide network interception agent. Guarantees that adult content, gambling, and phishing traffic are intercepted, **even if the user disables or uninstalls the browser extension**.

---

## Architecture Hybride (2 Couches de Sécurité)

```
[ Application / Navigateur ]
           │
           ├── (1) Résolution DNS (Port 53 UDP/TCP) ──> [ CyberGuard DNS Filter ]
           │                                                    │
           │                                                    ├─ Domaine bloqué  ──> Réponse 127.0.0.1 (Sinkhole)
           │                                                    └─ Domaine permis  ──> Forward DNS amont (1.1.1.1 / 8.8.8.8)
           │
           └── (2) Requête HTTP/HTTPS (Port 8899)    ──> [ CyberGuard HTTP/CONNECT Proxy ]
                                                                │
                                                                ├─ Inspection Politique MINESEC
                                                                ├─ Inspection IA Détection Phishing
                                                                └─ Si bloqué ──> HTTP 403 + Page de Blocage Personnalisée
```

### 1. Couche DNS (Sinkhole)
- Intercepte toutes les requêtes DNS de la machine hôte.
- Si le domaine est classé comme adulte, jeux d'argent ou malveillant selon la politique MINESEC, l'adresse retournée est `127.0.0.1`.
- Le trafic est ainsi neutralisé à la racine avant même qu'une connexion TCP ne s'établisse.

### 2. Couche Proxy Système (HTTP / CONNECT)
- Configuré de façon transparente dans les paramètres de proxy Windows (`HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`).
- Bloque les requêtes HTTP directes en renvoyant la page d'interdiction officielle CyberGuard.
- Intercepte les requêtes `CONNECT` (HTTPS) et coupe la poignée de main avec un code HTTP `403 Forbidden` sans nécessiter d'interception TLS intrusive (respect de la vie privée et intégrité cryptographique des certificats racine).

### 3. Télémétrie et SOC
- L'agent communique avec le backend FastAPI (`/api/v1/enterprise/agent/heartbeat` et `/api/v1/enterprise/agent/events`).
- Les statistiques en temps réel et les journaux de blocage sont visibles sur le tableau de bord Administrateur dans l'onglet **Paramètres**.

---

## Instructions d'Utilisation

### Lancement Standard (Administrateur)
Double-cliquez sur `run_agent.bat` ou lancez dans un terminal Administrateur :
```cmd
python cyberguard_agent.py run
```
*Note : L'élévation administrateur est requise par Windows uniquement pour modifier les serveurs DNS de la carte réseau active.*

### Restauration du Réseau
En cas d'arrêt (`Ctrl+C`), le script restaure **automatiquement** les paramètres DNS et proxy d'origine.
Si le processus est forcé ou en cas de coupure inopinée :
Double-cliquez sur `restore_network.bat` ou lancez :
```cmd
python cyberguard_agent.py restore
```

### Mode Test / Sandbox (Sans modification du système)
Pour tester l'agent sans modifier la configuration réseau de la machine :
```cmd
python cyberguard_agent.py run --no-system-config --dns-port 5353 --block-http-port 8081
```
Puis lancer le test automatisé :
```cmd
python selftest.py
```
