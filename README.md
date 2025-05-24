# Email Verifier

Webová aplikace pro verifikaci emailových adres pomocí SMTP a DNS kontrol. Aplikace poskytuje REST API a webové rozhraní pro hromadnou verifikaci emailových adres.

## Funkce

- Verifikace emailových adres pomocí SMTP a DNS kontrol
- Webové rozhraní pro nahrávání a zpracování souborů
- REST API pro programové využití
- Paralelní zpracování pro rychlou verifikaci
- Detekce catch-all domén s podporou pro Microsoft domény
- Detekce jednorázových emailových adres
- Rate limiting a ochrana proti blokování
- Detailní logování a reportování
- Asynchronní zpracování pro lepší výkon
- Podpora pro export výsledků ve formátech CSV a JSON
- Automatické opakování při dočasných chybách
- Inteligentní správa odesílacích adres pro citlivé domény
- Podpora pro Microsoft 365/Outlook.com domény
- Optimalizované zpracování chyb a výjimek

## Technické požadavky

- Python 3.8 nebo novější
- pip (správce balíčků Python)
- Virtuální prostředí (doporučeno)

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

4. Výsledky budou zobrazeny v tabulce a můžete je stáhnout ve formátu CSV nebo JSON

### REST API

Aplikace poskytuje REST API endpointy:

#### Verifikace emailů
```
POST /api/verify
Content-Type: application/json

{
    "emails": ["email1@domain.com", "email2@domain.com"]
}
```

#### Získání stavu verifikace
```
GET /api/status
```

#### Zastavení verifikace
```
POST /api/stop_verification
```

#### Stažení výsledků
```
GET /api/download_results
```

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
- `batch_size`: velikost dávky pro zpracování
- `max_concurrent_domains`: maximální počet souběžných domén
- `sender_emails_by_domain`: konfigurace odesílacích adres pro různé domény

## Výstup

Program generuje dva typy výstupů:
1. CSV soubor s výsledky verifikace obsahující:
   - Email adresa
   - Status verifikace
   - Detekovaná chyba (pokud existuje)
   - Typ domény (catch-all, jednorázová, atd.)
   - SMTP kód a odpověď
   - DNS záznamy
   - Čas verifikace

2. JSON soubor s detailními informacemi včetně:
   - Všechny informace z CSV
   - Detailní SMTP komunikace
   - Časové údaje
   - Verifikační kroky

## Logy

Logy jsou ukládány do adresáře `logs/` ve formátu:
```
YYYY-MM-DD HH:MM:SS - LEVEL - Message
```

## Bezpečnost

- Rate limiting pro ochranu SMTP serverů
- Validace vstupních dat
- Omezení velikosti nahrávaných souborů
- Ochrana proti DoS útokům
- Bezpečné zpracování SMTP komunikace
- Omezení počtu požadavků na API
- Inteligentní správa odesílacích adres
- Ochrana proti blokování IP adres

## Výkon

- Asynchronní zpracování pro maximální výkon
- Paralelní zpracování více emailů
- Optimalizované DNS dotazy
- Efektivní správa paměti
- Dávkové zpracování pro velké soubory
- Cachování DNS a catch-all výsledků
- Optimalizované opakování při chybách

## Licence

MIT License

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request 