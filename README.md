# DNS Checker

**Auteur:** Sigurd Felix  
**Versie:** 1.0 — 8 maart 2026  
**Contact:** sigurd@forevertoday.nl

> DNS Checker analyseert de DNS-configuratie van domeinen op e-mailbeveiliging en infrastructuur. Het resultaat is een overzichtelijk HTML-rapport of een gekleurde Excel-werkmap, waarbij groen, rood en grijs direct inzicht geven in de configuratiestatus.

---

## Inhoudsopgave

- [Wat doet DNS Checker?](#wat-doet-dns-checker)
- [Vereisten en installatie](#vereisten-en-installatie)
- [Opstarten](#opstarten)
- [Gebruiksmodes](#gebruiksmodes)
- [Uitvoer](#uitvoer)
- [Uitleg van de checks](#uitleg-van-de-checks)
- [Kleurcodes](#kleurcodes)
- [Mappenstructuur](#mappenstructuur)
- [Licentie](#licentie)
- [Disclaimer](#disclaimer)

---

## Wat doet DNS Checker?

DNS Checker controleert per domein een reeks DNS-records en geeft per bevinding aan of de configuratie goed, onvolledig of afwezig is. Het is bedoeld als hulpmiddel bij het snel in kaart brengen van de e-mailbeveiligingsstatus van een groot aantal domeinen, bijvoorbeeld bij een sectoranalyse of interne audit.

Gecontroleerde records per domein:

| Check | Wat wordt gecontroleerd |
|---|---|
| SPF | Aanwezigheid, strictheid, lookups, lengte, verzenders, dubbele records |
| DMARC | Policy, rapportage-adres (rua), percentage |
| DKIM | Microsoft (selector1/selector2) en Google (google/google2) |
| DNSSEC | Aanwezigheid van DNSKEY-record |
| MTA-STS | Aanwezigheid én policy-mode (enforce / testing) |
| BIMI | Aanwezigheid van default._bimi record |
| CAA | Certificate Authority Authorization records |
| security.txt | Aanwezigheid via HTTPS en HTTP |
| MX | Mailservers, provider-detectie, SMG-detectie |
| A / AAAA | IPv4, IPv6 |
| NS | Nameservers en DNS-provider |

---

## Vereisten en installatie

- Python 3.10 of hoger
- Internetverbinding

### Benodigde pakketten

```bash
pip install dnspython requests openpyxl
```

DNS Checker controleert bij opstarten automatisch of de benodigde pakketten aanwezig zijn en biedt aan ze automatisch te installeren als dat niet het geval is.

---

## Opstarten

Dubbelklik op `dns_checker.py`, of start via de command prompt:

```bash
python dns_checker.py
```

Bij de **eerste opstart** worden automatisch aangemaakt:
- De map `reports/` — voor alle uitvoerbestanden
- De map `docs/` — met README, LICENSE, DEPENDENCIES en versiebestand

Als `domains.txt` naast het script staat, start DNS Checker automatisch met die lijst. Anders verschijnt het opstartmenu.

---

## Gebruiksmodes

### Opstartmenu

```
╔══════════════════════════════════════════════════╗
║                  DNS Checker                     ║
╚══════════════════════════════════════════════════╝

  1. Een lijst met domeinen controleren (domains.txt)
  2. Een enkel domein controleren
  3. Over / disclaimer
  4. Afsluiten
```

Na elke uitvoering keer je terug naar het menu.

### Enkel domein — `--domain`

```bash
python dns_checker.py --domain mijnbedrijf.nl
python dns_checker.py --domain https://www.mijnbedrijf.nl
```

Uitvoer: `reports/dns_rapport_mijnbedrijf.nl_20260308_143022.html`

### Lijst van domeinen — `--domains`

```bash
python dns_checker.py --domains domains.txt
```

Het bestand `domains.txt` bevat één domein per regel. Commentaarregels beginnen met `#`. Een eerste headerregel `domain` wordt overgeslagen.

```
# DNS controle - maart 2026
domain
mijnbedrijf.nl
anderebedrijf.nl
derdebedrijf.nl
```

Uitvoer: `reports/dns_results_20260308_143022.xlsx`

### Geavanceerde opties

| Argument | Beschrijving | Standaard |
|---|---|---|
| `--domain` | Enkel domein controleren | — |
| `--domains` | Pad naar domains.txt | — |
| `--workers` | Aantal parallelle threads | 5 |
| `--timeout` | DNS timeout in seconden | 5 |
| `--no-input` | Geen interactieve vragen | uit |

```bash
python dns_checker.py --domains domains.txt --workers 10
python dns_checker.py --domains domains.txt --timeout 3 --no-input
```

---

## Uitvoer

Alle uitvoerbestanden worden opgeslagen in `reports/`.

### HTML-rapport (enkelvoudig domein)

Het rapport bevat een overall score, een aandachtspuntenblok en gedetailleerde secties:

- **Algemeen** — domein, checkdatum, IPv4/IPv6, NS-provider
- **E-mail & MX** — MX-records, mailprovider, SMG-detectie
- **SPF** — record, strictheid, lookups, lengte, verzenders, fouten
- **DMARC** — record, policy, rua, percentage
- **DKIM** — Microsoft en Google selectors
- **DNS & infra** — DNSSEC, MTA-STS + mode, BIMI, CAA, security.txt

Onderaan staat een informatieblok over de beveiliging van inactieve domeinen.

Het rapport is een **zelfstandig HTML-bestand** — geen externe afhankelijkheden, direct te openen in elke browser of te versturen per e-mail.

### Excel-werkmap (lijst van domeinen)

- Één rij per domein
- Cellen gekleurd op basis van configuratiestatus (groen / rood / grijs)
- Eerste rij en kolom A bevroren voor eenvoudig navigeren

---

## Uitleg van de checks

### SPF — Sender Policy Framework

SPF legt vast welke mailservers e-mail mogen versturen namens een domein.

| Waarde | Betekenis | Status |
|---|---|---|
| `-all` (hard fail) | Niet-geautoriseerde mail geweigerd | ✅ Goed |
| `~all` (soft fail) | Niet-geautoriseerde mail gemarkeerd | ✅ Goed |
| `+all` | Iedereen mag mailen — geen bescherming | ❌ Slecht |
| `?all` | Neutraal — ontvangende server doet niets | ❌ Slecht |

**DNS lookups:** RFC 7208 staat maximaal 10 toe, geteld recursief door alle includes heen.  
**Recordlengte:** Een enkel TXT-record mag maximaal 255 bytes zijn (RFC 4408).  
**Dubbele records:** RFC 7208 staat per domein maar één SPF-record toe.  
**Verzenders:** De tool klapt alle `include:`-mechanismen recursief uit en toont welke providers er achter zitten.

### DMARC

DMARC bouwt voort op SPF en DKIM en bepaalt wat er met niet-geauthenticeerde mail gebeurt.

| Policy | Effect |
|---|---|
| `p=none` | Geen actie — alleen rapportage (geen bescherming) |
| `p=quarantine` | Verdachte mail naar spam verplaatsen |
| `p=reject` | Verdachte mail weigeren |

Zonder `rua` ontvang je geen meldingen over misbruik van je domein.  
Aanbevolen uitrolpad: `none` → `quarantine` → `reject`.

### DKIM — DomainKeys Identified Mail

DKIM voegt een cryptografische handtekening toe aan uitgaande e-mail.  
DNS Checker controleert de meest gangbare selectors:

| Provider | Selectors |
|---|---|
| Microsoft 365 | `selector1`, `selector2` |
| Google Workspace | `google`, `google2` |

Microsoft 365 publiceert DKIM-records soms als CNAME — de tool volgt dit automatisch.  
Niet-gevonden selectors zijn **grijs**: andere selectors kunnen in gebruik zijn.

### DNSSEC

Voegt digitale handtekeningen toe aan DNS-antwoorden en beschermt tegen DNS-vervalsing (cache poisoning). DNS Checker controleert de aanwezigheid van een DNSKEY-record.

### MTA-STS

MTA-STS dwingt verzendende mailservers TLS te gebruiken bij aflevering.

| Mode | Betekenis |
|---|---|
| `enforce` | TLS volledig afgedwongen ✅ |
| `testing` | Actief maar TLS nog niet afgedwongen ⚠️ |
| `none` | Geen bescherming ⚠️ |

De tool haalt de policy op via `https://mta-sts.{domein}/.well-known/mta-sts.txt`.

### BIMI

BIMI maakt het mogelijk een merklogo te tonen in ondersteunde e-mailclients (Gmail, Apple Mail). Vereist DMARC met `p=quarantine` of `p=reject`.

### security.txt

Gestandaardiseerd bestand (RFC 9116) waarmee organisaties aangeven hoe beveiligingsonderzoekers kwetsbaarheden kunnen melden. Gecontroleerd op:
- `https://{domein}/.well-known/security.txt`
- `https://{domein}/security.txt`

### CAA — Certification Authority Authorization

CAA-records beperken welke certificaatautoriteiten SSL/TLS-certificaten mogen uitgeven voor een domein.

---

## Kleurcodes

| Kleur | Betekenis |
|---|---|
| 🟢 Groen | Configuratie correct en conform best practices |
| 🔴 Rood | Aandacht vereist — ontbreekt of onjuist geconfigureerd |
| ⬜ Grijs | Niet van toepassing, niet gevonden of neutraal |
| Wit | Puur informatief — geen kwaliteitsoordeel |

---

## Mappenstructuur

Na de eerste opstart:

```
dns_checker.py
├── domains.txt          ← optioneel invoerbestand
├── reports/             ← alle uitvoerbestanden
│   ├── dns_rapport_mijnbedrijf.nl_20260308_143022.html
│   └── dns_results_20260308_143022.xlsx
└── docs/                ← documentatie (automatisch gegenereerd)
    ├── README.txt
    ├── LICENSE.txt
    ├── DEPENDENCIES.txt
    └── VERSION_1.0.txt
```

---

## Licentie

**Vrije gebruikslicentie met verplichte naamsvermelding.**

Iedereen mag dit script vrij gebruiken, kopiëren, aanpassen en verspreiden — ook commercieel — onder twee voorwaarden:

1. De vermelding **© Sigurd Felix** blijft aanwezig in alle gegenereerde rapporten.
2. De auteursinformatie blijft aanwezig in de broncode.

Zie `docs/LICENSE.txt` voor de volledige licentietekst.

---

## Disclaimer

Dit script is ontwikkeld met behulp van Claude (Anthropic) en wordt aangeboden zoals het is. Er worden geen garanties gegeven over de juistheid van de uitkomsten of de werking in de toekomst. De gehanteerde beoordelingscriteria zijn subjectief. Aan de uitkomsten kunnen geen rechten worden ontleend.

Raadpleeg altijd een specialist voor definitieve conclusies over de beveiliging van een domein.

---

*© Sigurd Felix — dns_checker.py*
