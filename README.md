# Email Verifier

Webová aplikace pro verifikaci emailových adres pomocí SMTP a DNS kontrol. Aplikace poskytuje webové rozhraní pro hromadnou verifikaci emailových adres.

## Hlavní funkce

- Verifikace emailových adres pomocí SMTP a DNS kontrol
- Webové rozhraní pro nahrávání a zpracování souborů
- Paralelní zpracování pro rychlou verifikaci
- Detekce catch-all domén a jednorázových emailových adres
- Rate limiting a ochrana proti blokování
- Detailní logování a reportování
- Export výsledků ve formátu CSV

## Instalace

1. Klonování repozitáře:
```bash
git clone https://github.com/yourusername/email-verifier.git
cd email-verifier
```

2. Vytvoření virtuálního prostředí:
```bash
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
# nebo
.venv\Scripts\activate  # Windows
```

3. Instalace závislostí:
```bash
pip install -r requirements.txt
```

## Použití

### Webové rozhraní

1. Spusťte aplikaci:
```bash
python app.py
```

2. Otevřete webový prohlížeč a přejděte na `http://localhost:5000`

3. Nahrajte soubor s emaily (jeden email na řádek) nebo zadejte emaily přímo do formuláře

## Konfigurace

Konfigurační soubor `config.json` umožňuje nastavit:
- `timeout`: časový limit pro SMTP operace (v sekundách)
- `max_workers`: počet paralelních vláken
- `catchall_test`: povolení testu catch-all domén
- `connect_port`: SMTP port pro připojení
- `retry_attempts`: počet pokusů o opakování při selhání
- `retry_delay`: zpoždění mezi pokusy (v sekundách)
- `rate_limit_delay`: zpoždění při rate limitu (v sekundách)
- `check_disposable`: kontrola jednorázových emailů
- `check_catchall`: kontrola catch-all domén
- `max_concurrent_domains`: maximální počet souběžných domén
- `sender_emails_by_domain`: konfigurace odesílacích adres pro různé domény

## Výstup

Program generuje CSV soubor s výsledky verifikace obsahující:
- Email adresa
- Status verifikace
- Detekovaná chyba (pokud existuje)
- Typ domény (catch-all, jednorázová, atd.)
- SMTP kód a odpověď
- DNS záznamy
- Čas verifikace

## Licence

MIT License 