# mem-forensics-volatility

Analyse forensique d'une image mémoire Windows XP infectée par WannaCry avec Volatility 2 : processus, persistance, résidus SMB liés à EternalBlue, kill-switch et règles YARA.

## Description

Deux exercices menés sur la même image mémoire : Windows XP SP3 x86, capturée le 2017-05-12 à 21:26:32 UTC, SHA-256 `76E8BE1A…95AD2BF0`. Chaque fichier de `logs/` correspond à une question et contient la sortie brute de l'outil.

### Exercice 4 : identification de l'infection

| Question | Méthode | Constat |
|---|---|---|
| q1 | `Get-FileHash`, `imageinfo` | Empreinte SHA-256 de l'image ; profil `WinXPSP2x86`, 1 CPU, sans PAE |
| q2 | `pslist` | `tasksche.exe` (PID 1940, parent `explorer.exe`) lance `@WanaDecryptor@` (PID 740) |
| q3 | `cmdline` | `tasksche.exe` s'exécute depuis `C:\Intel\ivecuqmanpnirkt615\` (dossier au nom aléatoire) |
| q4 | `hivelist`, `printkey` | Valeur `ivecuqmanpnirkt615` dans la clé `Run` de la ruche SOFTWARE : persistance au démarrage |
| q5 | chaînes | `WANACRY!`, `WanaCrypt0r`, `mssecsvc2.0`, `@WanaDecryptor@` |
| q7 | chaînes | Extensions ciblées : `.doc`, `.jpg`, `.pdf`, `.png`, `.ppt`, `.xls`, `.zip`… |

### Exercice 5 : vecteur SMB / EternalBlue

| Question | Méthode | Constat |
|---|---|---|
| q1 | `connections`, `connscan`, `sockets`, `sockscan` | Aucune connexion TCP, active ou résiduelle ; `System` écoute sur 445/TCP et 139/TCP (victime : 192.168.56.101) |
| q2 | `modules`, `modscan` | Pilote serveur SMB `srv.sys` chargé à `0xf75fa000` |
| q3 | `moddump` + chaînes | Extraction de `srv.sys` et recherche de traces WannaCry / DoublePulsar |
| q4 | scan des en-têtes `FF 53 4D 42` | 44 en-têtes SMBv1 en mémoire. Un fragment à l'offset `0x1ACAD548` enchaîne Negotiate (`0x72`), Session Setup (`0x73`, NativeOS `Windows 2000 2195`), Tree Connect `\\192.168.56.20\IPC$` (`0x75`) puis deux Trans2 (`0x32`) |
| q5 | `memdump` + expressions régulières | Adresses IP en mémoire : 192.168.56.1, .101, .20 |
| q6 | chaînes (image entière / mémoire de processus) | Domaine kill-switch `iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com` présent dans l'image, absent de la mémoire des PID 1940 et 740 |
| q7 | YARA | Deux règles de détection (voir `yara/`) |

## Stack technique

- Volatility 2 via l'image Docker `cincan/volatility`
- Wrappers Bash et PowerShell (conteneur éphémère, système de fichiers en lecture seule)
- YARA
- PowerShell (`Get-FileHash`, recherche de chaînes et d'expressions régulières)

## Structure

```
.
├── scripts/
│   ├── vol.sh                         # Wrapper Docker (Linux / macOS / WSL)
│   └── vol.ps1                        # Wrapper Docker (Windows PowerShell)
├── yara/
│   └── eternalblue_doublepulsar.yar   # Règles EternalBlue (résidus SMBv1) et DoublePulsar
└── logs/
    ├── exo4-wannacry/                 # Sorties brutes, une par question
    └── exo5-smb-eternalblue/
```

L'image mémoire (512 Mo) et les extractions ne sont pas publiées. Les fichiers `.dmp` et `.sys` sont la mémoire de processus et un pilote d'un système infecté : on ne les héberge pas.

## Installation et lancement

Prérequis : Docker, et YARA pour l'étape de détection. Se placer à la racine du dépôt (monté sur `/data` dans le conteneur) et déposer l'image mémoire dans `dumps/` (ignoré par git).

```bash
chmod +x scripts/vol.sh
sha256sum dumps/exercice4.raw
./scripts/vol.sh -f /data/dumps/exercice4.raw imageinfo
./scripts/vol.sh -f /data/dumps/exercice4.raw --profile=WinXPSP2x86 pslist
./scripts/vol.sh -f /data/dumps/exercice4.raw --profile=WinXPSP2x86 cmdline
./scripts/vol.sh -f /data/dumps/exercice4.raw --profile=WinXPSP2x86 printkey -K "Microsoft\Windows\CurrentVersion\Run"
./scripts/vol.sh -f /data/dumps/exercice4.raw --profile=WinXPSP2x86 sockscan
./scripts/vol.sh -f /data/dumps/exercice4.raw --profile=WinXPSP2x86 moddump --base=0xf75fa000 -D /data/extractions
./scripts/vol.sh -f /data/dumps/exercice4.raw --profile=WinXPSP2x86 memdump -p 1940 -D /data/extractions
yara -s yara/eternalblue_doublepulsar.yar dumps/exercice4.raw
```

Sous Windows, remplacer `./scripts/vol.sh` par `.\scripts\vol.ps1` (mêmes arguments). L'image Docker utilisée peut être changée via la variable `VOL_IMAGE`.

## Ce que j'ai appris / côté sécurité

- **Recouper chaque constat.** Le processus suspect (`pslist`) est confirmé par son chemin d'exécution anormal (`cmdline`), puis par une persistance qui pointe exactement vers ce chemin (`printkey`). Une preuve isolée ne suffit pas.
- **Pas de connexion ne veut pas dire pas d'activité réseau.** `connscan` ne renvoie rien, mais les buffers noyau contiennent encore des en-têtes SMBv1 : le trafic passé laisse des traces que les plugins réseau ne montrent pas.
- **Attention aux conclusions trop rapides.** `\\192.168.56.20\IPC$` et `Windows 2000 2195` sont des chaînes codées en dur dans les paquets EternalBlue embarqués par WannaCry. Leur présence en mémoire signe l'exploit, mais ne prouve pas à elle seule un échange avec l'hôte 192.168.56.20.
- **Le kill-switch absent des processus dumpés est cohérent avec WannaCry** : la vérification du domaine est faite par le composant ver (service `mssecsvc2.0`), pas par le chiffreur `tasksche.exe`.
- **Écrire une règle YARA, c'est aussi indiquer son niveau de confiance.** La règle DoublePulsar est marquée « non confirmée ». Ses motifs d'opcode sur un seul octet (`{ 51 }`, `{ 52 }`) correspondent à presque n'importe quel contenu : en pratique, la règle repose sur ses autres conditions. Il faudrait des motifs plus longs et plus spécifiques.
- **Intégrité de la preuve.** L'image est hachée avant analyse, et le conteneur est éphémère avec un système de fichiers en lecture seule (`--read-only`, `/tmp` en tmpfs). Le dossier monté reste accessible en écriture, car `moddump` et `memdump` y déposent leurs extractions. Amélioration : monter `dumps/` en lecture seule (`:ro`) et écrire les extractions dans un volume séparé.
