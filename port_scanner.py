#!/usr/bin/env python3
"""
Advanced TCP Port Scanner
Author : Sami De Waal
Description : Scanner de ports TCP multi-threadé avec détection de services,
              banner grabbing et repérage de vulnérabilités connues par port.
GitHub : https://github.com/dewaalsami359

⚠️  USAGE LÉGAL UNIQUEMENT : ne scannez que des machines qui vous appartiennent
    ou pour lesquelles vous avez une autorisation écrite. Un scan non autorisé
    peut constituer un délit (art. 323-1 et s. du Code pénal).

Exemples :
    python port_scanner.py -t 127.0.0.1 -p 1-1000
    python port_scanner.py -t scanme.nmap.org -p common --threads 100
    python port_scanner.py -t 192.168.1.10 -p 22,80,443 -o resultats.json
"""

import socket
import argparse
import sys
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# Ports fréquemment rencontrés et leur service associé
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
}

# Vulnérabilités connues associées à certains ports (indicatif, non exhaustif)
KNOWN_VULNS = {
    21: ["FTP anonyme possible", "Backdoor vsftpd 2.3.4"],
    22: ["Clés SSH faibles", "Énumération d'utilisateurs OpenSSH"],
    445: ["MS17-010 (EternalBlue)", "SMBGhost CVE-2020-0796"],
    3306: ["Contournement d'authentification MySQL CVE-2012-2122"],
    3389: ["BlueKeep CVE-2019-0708"],
}


class PortScanner:
    """Scanner de ports TCP multi-threadé."""

    def __init__(self, target, ports, timeout=1.0, max_threads=100):
        self.target = self._resolve_hostname(target)
        self.ports = ports
        self.timeout = timeout
        self.max_threads = max_threads
        self.results = []

    def _resolve_hostname(self, hostname):
        """Résout un nom d'hôte en adresse IP."""
        try:
            ip = socket.gethostbyname(hostname)
            print(f"[*] Cible résolue : {hostname} -> {ip}")
            return ip
        except socket.gaierror:
            print(f"[-] Erreur : impossible de résoudre '{hostname}'")
            sys.exit(1)

    def _grab_banner(self, sock):
        """Tente de récupérer la bannière d'un service (identification)."""
        try:
            sock.settimeout(self.timeout)
            banner = sock.recv(1024).decode(errors="ignore").strip()
            return banner if banner else None
        except Exception:
            return None

    def _scan_port(self, port):
        """Scanne un port unique et renvoie un dictionnaire de résultat s'il est ouvert."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(self.timeout)
            if sock.connect_ex((self.target, port)) == 0:
                banner = self._grab_banner(sock)
                return {
                    "port": port,
                    "service": COMMON_PORTS.get(port, "inconnu"),
                    "banner": banner,
                    "vulns": KNOWN_VULNS.get(port, []),
                }
        return None

    def scan(self):
        """Lance le scan multi-threadé sur l'ensemble des ports."""
        start = datetime.now()
        print(f"[*] Début du scan de {len(self.ports)} ports "
              f"({self.max_threads} threads)\n")

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(self._scan_port, p): p for p in self.ports}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    self.results.append(result)
                    line = f"[+] Port {result['port']:>5}/tcp  ouvert  ({result['service']})"
                    if result["banner"]:
                        line += f"  | {result['banner'][:60]}"
                    print(line)
                    for vuln in result["vulns"]:
                        print(f"      ⚠  {vuln}")

        self.results.sort(key=lambda r: r["port"])
        duration = (datetime.now() - start).total_seconds()
        print(f"\n[*] Scan terminé en {duration:.2f}s "
              f"— {len(self.results)} port(s) ouvert(s)")
        return self.results

    def export_json(self, filepath):
        """Exporte les résultats au format JSON."""
        report = {
            "target": self.target,
            "date": datetime.now().isoformat(),
            "open_ports": self.results,
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"[*] Rapport exporté : {filepath}")


def parse_ports(port_spec):
    """Transforme une spécification de ports en liste d'entiers.

    Accepte : 'common', 'all', '1-1000', '80,443,8080', ou une combinaison.
    """
    if port_spec == "common":
        return sorted(COMMON_PORTS.keys())
    if port_spec == "all":
        return list(range(1, 65536))

    ports = set()
    for part in port_spec.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            ports.update(range(int(start), int(end) + 1))
        elif part:
            ports.add(int(part))
    return sorted(ports)


def main():
    parser = argparse.ArgumentParser(
        description="Scanner de ports TCP multi-threadé (usage légal uniquement)."
    )
    parser.add_argument("-t", "--target", required=True,
                        help="IP ou nom d'hôte de la cible")
    parser.add_argument("-p", "--ports", default="common",
                        help="Ports à scanner : 'common', 'all', '1-1000' ou '80,443'")
    parser.add_argument("--threads", type=int, default=100,
                        help="Nombre de threads (défaut : 100)")
    parser.add_argument("--timeout", type=float, default=1.0,
                        help="Timeout par port en secondes (défaut : 1.0)")
    parser.add_argument("-o", "--output",
                        help="Fichier JSON de sortie (optionnel)")
    args = parser.parse_args()

    scanner = PortScanner(
        target=args.target,
        ports=parse_ports(args.ports),
        timeout=args.timeout,
        max_threads=args.threads,
    )
    scanner.scan()
    if args.output:
        scanner.export_json(args.output)


if __name__ == "__main__":
    main()
