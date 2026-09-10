# 🔍 Advanced TCP Port Scanner

Scanner de ports TCP multi-threadé écrit en Python, avec détection de services, *banner grabbing* et repérage de vulnérabilités connues par port.

![Python](https://img.shields.io/badge/Python-3.7%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/usage-l%C3%A9gal%20uniquement-red)

## 📋 Description

Ce projet reproduit, à petite échelle, les fonctionnalités de base d'un outil comme Nmap. Il m'a servi à approfondir la programmation réseau (sockets TCP), le multi-threading en Python et la phase de *reconnaissance* d'un test d'intrusion.

## ✨ Fonctionnalités

- **Scan TCP multi-threadé** (jusqu'à plusieurs centaines de threads)
- **Détection de services** sur les ports courants (SSH, HTTP, SMB, MySQL…)
- **Banner grabbing** — récupération de la bannière renvoyée par le service
- **Repérage de vulnérabilités connues** associées à certains ports (indicatif)
- **Export JSON** du rapport de scan
- Gestion des plages (`1-1000`), des listes (`80,443,8080`) et des raccourcis (`common`, `all`)

## 🚀 Utilisation

```bash
# Scanner les ports courants d'une machine locale
python port_scanner.py -t 127.0.0.1 -p common

# Scanner une plage avec 100 threads
python port_scanner.py -t scanme.nmap.org -p 1-1000 --threads 100

# Scanner des ports précis et exporter le rapport
python port_scanner.py -t 192.168.1.10 -p 22,80,443 -o resultats.json
```

### Options

| Option | Description |
|--------|-------------|
| `-t, --target` | IP ou nom d'hôte de la cible (obligatoire) |
| `-p, --ports` | Ports : `common`, `all`, `1-1000` ou `80,443` |
| `--threads` | Nombre de threads (défaut : 100) |
| `--timeout` | Timeout par port en secondes (défaut : 1.0) |
| `-o, --output` | Fichier JSON de sortie (optionnel) |

## 🛠️ Technologies

Python 3 · `socket` · `concurrent.futures` (ThreadPoolExecutor) · `argparse` · `json`

## ⚠️ Avertissement légal

Cet outil est fourni à des fins **pédagogiques**. Ne scannez que des systèmes qui vous appartiennent ou pour lesquels vous disposez d'une **autorisation écrite**. Un scan non autorisé peut constituer un délit (articles 323-1 et suivants du Code pénal). L'auteur décline toute responsabilité en cas d'usage abusif.

## 👤 Auteur

**Sami De Waal** — Étudiant ingénieur cybersécurité, EFREI Paris
🔗 [linkedin.com/in/samidewaal](https://linkedin.com/in/samidewaal)
