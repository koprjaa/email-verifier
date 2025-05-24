import asyncio
import csv
import io
import json
import logging
import os
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List

from flask import Flask, jsonify, render_template, request, send_file
from flask_cors import CORS
from werkzeug.utils import secure_filename

# Předpokládáme, že EmailVerifier je v src.verifier.email_verifier
# Upravte cestu podle vaší struktury projektu
from email_verifier import EmailVerifier # Přímý import, pokud je ve stejném adresáři pro jednoduchost
                                         # nebo from src.verifier.email_verifier import EmailVerifier

# --- Konfigurace aplikace ---
app = Flask(__name__)
CORS(app) # Povolení CORS pro všechny routy (pro produkci omezit)
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10MB max upload
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['RESULTS_FOLDER'] = 'results'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['RESULTS_FOLDER'], exist_ok=True)

# --- Logování ---
# Použijeme logger z Flasku, který je již nakonfigurován
# Pokud chcete detailnější konfiguraci, můžete ji provést zde
app.logger.setLevel(logging.INFO) # Pro produkci INFO, pro debug DEBUG
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(threadName)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
if not app.logger.handlers: # Přidat handler pouze pokud ještě žádný není
    app.logger.addHandler(handler)


# --- Globální instance EmailVerifier ---
# Načtení konfigurace pro EmailVerifier (může být z config.json nebo definováno zde)
# Pro jednoduchost použijeme výchozí hodnoty nebo je můžeme načíst z fiktivního config.json
try:
    with open('config_verifier.json', 'r') as f: # Přejmenováno, aby nekolidovalo s Flask configem
        verifier_config = json.load(f)
    app.logger.info("Konfigurace pro EmailVerifier načtena z config_verifier.json")
except FileNotFoundError:
    app.logger.warning("Soubor config_verifier.json nenalezen, použijí se výchozí hodnoty pro EmailVerifier.")
    verifier_config = {} # Prázdný slovník, EmailVerifier použije své defaulty

# Vytvoření jedné globální instance EmailVerifier
# skip_signal_handlers=True je důležité, protože signály bude řešit WSGI server (Flask dev server, Gunicorn, atd.)
email_verifier_instance = EmailVerifier(
    timeout=verifier_config.get('timeout', 15),
    smtp_timeout=verifier_config.get('smtp_timeout', 10),
    dns_timeout=verifier_config.get('dns_timeout', 5),
    # max_workers je parametr, který EmailVerifier nepoužívá, odstraňuji
    catchall_test_enabled=verifier_config.get('catchall_test_enabled', True),
    connect_port=verifier_config.get('connect_port', 25),
    rate_limit_delay_base=verifier_config.get('rate_limit_delay_base', 2.0),
    batch_size=verifier_config.get('batch_size_internal_verifier', 50), # Interní batch_size verifieru
    max_concurrent_domains=verifier_config.get('max_concurrent_domains', 5),
    helo_hostname=verifier_config.get('helo_hostname', None), # None použije fqdn
    retry_attempts=verifier_config.get('retry_attempts', 2),
    retry_delay_base=verifier_config.get('retry_delay_base', 5.0),
    # Cesty k souborům pro progress a adaptivní parametry jsou již ve třídě EmailVerifier
    skip_signal_handlers=True
)
app.logger.info("Globální instance EmailVerifier byla vytvořena.")

# --- Globální stav pro hromadnou verifikaci ---
# Tento stav bude sdílen mezi requesty (pro jeden proces Flasku)
# Pro více procesů (např. Gunicorn s více workery) by bylo potřeba externí úložiště (Redis, atd.)
current_verification_state: Dict[str, Any] = {}
verification_lock = threading.Lock() # Zámek pro synchronizaci přístupu ke globálnímu stavu
bulk_verification_thread = None # Reference na vlákno hromadné verifikace

def reset_verification_state():
    """Resetuje globální stav hromadné verifikace."""
    global current_verification_state
    with verification_lock:
        current_verification_state = {
            'status': 'idle', # idle, loading_csv, selecting_column, ready_to_verify, verifying, completed, stopped, error
            'error_message': None,
            'uploaded_filepath': None, # Cesta k nahranému CSV
            'selected_column': None,
            'emails_to_verify': [],
            'total_emails': 0,
            'processed_emails': 0,
            'valid_emails': 0,
            'invalid_emails': 0,
            'probable_emails': 0, # Catch-all, ale jinak validní syntax
            'unknown_emails': 0,  # Chyby, timeouty
            'current_batch_num': 0,
            'total_batches': 0,
            'results': {}, # Klíč: email, Hodnota: výsledek z EmailVerifier
            'verification_log': [], # Log kroků pro frontend
            'start_time': None,
            'last_activity_time': None,
            'result_filepath': None, # Cesta k finálnímu souboru s výsledky
            'accept_all_domains_summary': {}, # domain -> count
            'stop_requested': False,
            'verification_run_id': None # Pro odlišení běhů, pokud by bylo potřeba
        }
        # Resetovat i interní stav EmailVerifier pro nový běh (pokud je to relevantní)
        # email_verifier_instance.reset_run_state() # Pokud taková metoda existuje
        app.logger.info("Globální stav verifikace byl resetován na 'idle'.")

reset_verification_state() # Inicializace stavu při startu aplikace

# --- Endpointy ---

@app.route('/')
def index():
    """Zobrazí hlavní stránku."""
    return render_template('index.html')

@app.route('/verify_single', methods=['POST'])
async def verify_single_email_route(): # Flask může mít async routy s ASGI serverem
    """Ověří jeden email."""
    data = request.json
    email_to_verify = data.get('email')

    if not email_to_verify:
        app.logger.warning("API /verify_single: Chybí email v požadavku.")
        return jsonify({'error': 'Chybí email v požadavku'}), 400

    app.logger.info(f"API /verify_single: Ověřování emailu: {email_to_verify}")
    try:
        # Použití globální instance EmailVerifier
        # Pokud Flask běží na synchronním serveru (jako je výchozí Werkzeug),
        # musíme `async` kód spustit explicitně.
        # Vlákno Flasku má svůj vlastní loop, nebo `asyncio.run` vytvoří nový.
        if threading.current_thread() is threading.main_thread() and not asyncio.get_event_loop().is_running():
             result = asyncio.run(email_verifier_instance.verify_single_email(email_to_verify))
        else:
            # Pokud jsme již v běžícím loopu (např. v testech nebo s ASGI serverem)
             result = await email_verifier_instance.verify_single_email(email_to_verify)

        app.logger.info(f"API /verify_single: Výsledek pro {email_to_verify}: {result.get('status_code')}")
        return jsonify(result)
    except Exception as e:
        app.logger.error(f"API /verify_single: Chyba při ověřování emailu {email_to_verify}: {e}", exc_info=True)
        return jsonify({'error': f'Interní chyba serveru: {str(e)}'}), 500


@app.route('/load_csv', methods=['POST'])
def load_csv_route():
    """Načte CSV soubor a vrátí seznam sloupců."""
    with verification_lock:
        if current_verification_state['status'] not in ['idle', 'error', 'completed', 'stopped']:
            return jsonify({'error': 'Jiná operace již probíhá.'}), 400
        reset_verification_state() # Resetovat stav pro nové nahrání
        current_verification_state['status'] = 'loading_csv'

    if 'file' not in request.files:
        with verification_lock: current_verification_state['status'] = 'error'
        return jsonify({'error': 'Soubor nebyl poskytnut'}), 400

    file = request.files['file']
    if file.filename == '':
        with verification_lock: current_verification_state['status'] = 'error'
        return jsonify({'error': 'Nebyl vybrán žádný soubor'}), 400

    if not file.filename.lower().endswith('.csv'):
        with verification_lock: current_verification_state['status'] = 'error'
        return jsonify({'error': 'Povoleny jsou pouze CSV soubory'}), 400

    filename = secure_filename(file.filename)
    uploaded_filepath = Path(app.config['UPLOAD_FOLDER']) / f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{filename}"

    try:
        file.save(uploaded_filepath)
        app.logger.info(f"API /load_csv: Soubor '{filename}' uložen do '{uploaded_filepath}'.")

        # Detekce hlaviček (jednoduchá)
        # Pro robustnější řešení zvažte detekci kódování a oddělovače
        detected_encoding = None
        encodings_to_try = ['utf-8-sig', 'utf-8', 'cp1250', 'iso-8859-2']
        headers = []

        for enc in encodings_to_try:
            try:
                with open(uploaded_filepath, 'r', encoding=enc) as f:
                    reader = csv.reader(f)
                    headers = next(reader) # Přečíst první řádek jako hlavičky
                    detected_encoding = enc
                    app.logger.info(f"API /load_csv: Soubor úspěšně přečten s kódováním '{enc}'. Hlavičky: {headers}")
                    break
            except (UnicodeDecodeError, StopIteration):
                continue # Zkusit další kódování nebo pokud je soubor prázdný

        if not headers:
            os.remove(uploaded_filepath) # Smazat nevalidní soubor
            with verification_lock: current_verification_state['status'] = 'error'
            app.logger.error("API /load_csv: Nepodařilo se přečíst hlavičky ze CSV souboru.")
            return jsonify({'error': 'Nepodařilo se přečíst CSV soubor. Zkontrolujte kódování a formát.'}), 400

        # Sugesce emailového sloupce
        suggested_column = None
        common_email_headers = ['email', 'e-mail', 'mail', 'emailaddress']
        for header in headers:
            if header.lower().replace(" ", "").replace("_", "") in common_email_headers:
                suggested_column = header
                break
        if not suggested_column and headers:
            suggested_column = headers[0] # Výchozí první sloupec

        with verification_lock:
            current_verification_state['uploaded_filepath'] = str(uploaded_filepath)
            current_verification_state['status'] = 'selecting_column'
            current_verification_state['detected_encoding'] = detected_encoding # Uložit pro pozdější čtení

        return jsonify({
            'status': 'select_column',
            'columns': headers,
            'suggested_email_column': suggested_column
        })

    except Exception as e:
        if uploaded_filepath and os.path.exists(uploaded_filepath):
            os.remove(uploaded_filepath)
        with verification_lock:
            current_verification_state['status'] = 'error'
            current_verification_state['error_message'] = str(e)
        app.logger.error(f"API /load_csv: Chyba při zpracování CSV: {e}", exc_info=True)
        return jsonify({'error': f'Chyba při zpracování CSV: {str(e)}'}), 500


@app.route('/select_column', methods=['POST'])
def select_column_route():
    """Zpracuje výběr sloupce s emaily."""
    with verification_lock:
        if current_verification_state['status'] != 'selecting_column':
            return jsonify({'error': 'Neplatný stav pro výběr sloupce.'}), 400

    data = request.json
    selected_column = data.get('column')

    if not selected_column:
        return jsonify({'error': 'Nebyl vybrán žádný sloupec'}), 400

    uploaded_filepath = current_verification_state.get('uploaded_filepath')
    detected_encoding = current_verification_state.get('detected_encoding', 'utf-8') # Použít detekované kódování

    if not uploaded_filepath:
        return jsonify({'error': 'Nejprve nahrajte CSV soubor'}), 400

    try:
        emails_to_verify = []
        with open(uploaded_filepath, 'r', encoding=detected_encoding) as f:
            reader = csv.DictReader(f) # Použít DictReader pro snadný přístup podle názvu sloupce
            if selected_column not in reader.fieldnames:
                app.logger.error(f"API /select_column: Sloupec '{selected_column}' nenalezen. Dostupné: {reader.fieldnames}")
                return jsonify({'error': f"Sloupec '{selected_column}' nebyl v CSV nalezen."}), 400

            for row in reader:
                email = row.get(selected_column, "").strip()
                if email: # Přidat pouze neprázdné emaily
                    emails_to_verify.append(email)
        
        # Odstranit duplicity při zachování pořadí
        seen = set()
        unique_emails = [x for x in emails_to_verify if not (x in seen or seen.add(x))]

        app.logger.info(f"API /select_column: Vybrán sloupec '{selected_column}'. Nalezeno {len(unique_emails)} unikátních emailů.")

        if not unique_emails:
            return jsonify({'error': f"Ve sloupci '{selected_column}' nebyly nalezeny žádné platné emailové adresy."}), 400

        with verification_lock:
            current_verification_state['selected_column'] = selected_column
            current_verification_state['emails_to_verify'] = unique_emails
            current_verification_state['total_emails'] = len(unique_emails)
            current_verification_state['status'] = 'ready_to_verify'

        return jsonify({
            'status': 'ready', # Frontend očekává 'ready'
            'total_emails': len(unique_emails)
        })

    except Exception as e:
        with verification_lock:
            current_verification_state['status'] = 'error'
            current_verification_state['error_message'] = str(e)
        app.logger.error(f"API /select_column: Chyba při extrakci emailů: {e}", exc_info=True)
        return jsonify({'error': f'Chyba při extrakci emailů z CSV: {str(e)}'}), 500


def run_bulk_verification_in_thread():
    """Funkce, která běží ve vlákně a provádí hromadnou verifikaci."""
    global current_verification_state # Přístup ke globálnímu stavu
    run_id = None

    with verification_lock:
        # Ujistěte se, že běží pouze jedna instance této funkce pro daný run_id
        if current_verification_state.get('is_thread_active', False):
            app.logger.warning("Vlákno pro hromadnou verifikaci je již aktivní. Nové spuštění ignorováno.")
            return
        current_verification_state['is_thread_active'] = True
        run_id = current_verification_state.get('verification_run_id')


    app.logger.info(f"Vlákno (ID: {run_id}): Spouštění hromadné verifikace.")
    emails_this_run = list(current_verification_state.get('emails_to_verify', [])) # Kopie pro toto vlákno
    total_emails_this_run = len(emails_this_run)
    
    # Reset interního stavu EmailVerifier, pokud je to potřeba pro nový běh
    # email_verifier_instance.reset_run_state() # Důležité pro čištění cache mezi běhy, pokud je to žádoucí

    # Interní dávkování pro volání `verify_emails_in_batch`
    # Může být menší než batch_size, kterou má `EmailVerifier` interně pro paralelizaci.
    # Toto je spíše pro aktualizaci UI a možnost přerušení.
    app_batch_size = 20 # Kolik emailů zpracovat před aktualizací stavu a kontrolou přerušení

    for i in range(0, total_emails_this_run, app_batch_size):
        with verification_lock:
            if current_verification_state.get('stop_requested') or \
               current_verification_state.get('verification_run_id') != run_id: # Pokud byl spuštěn nový běh
                app.logger.info(f"Vlákno (ID: {run_id}): Detekován požadavek na zastavení nebo nový běh. Ukončuji.")
                current_verification_state['status'] = 'stopped'
                break
            
            current_verification_state['last_activity_time'] = time.time()
            current_verification_state['current_batch_num'] = (i // app_batch_size) + 1
            # total_batches se může vypočítat z total_emails_this_run a app_batch_size

        batch_to_process = emails_this_run[i : i + app_batch_size]
        app.logger.info(f"Vlákno (ID: {run_id}): Zpracovávám dávku {current_verification_state['current_batch_num']} ({len(batch_to_process)} emailů).")

        try:
            # Použití asyncio.run pro volání async metody z vlákna
            batch_results = asyncio.run(email_verifier_instance.verify_emails_in_batch(batch_to_process))
        except RuntimeError as e: # Zpracování chyb event loopu
            if "cannot run event loop while another loop is running" in str(e) or "Event loop is closed" in str(e):
                app.logger.warning(f"Vlákno (ID: {run_id}): Problém s event loopem: {e}. Pokus o vytvoření nového loopu.")
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    batch_results = loop.run_until_complete(email_verifier_instance.verify_emails_in_batch(batch_to_process))
                finally:
                    loop.close() # Důležité zavřít loop, který jsme vytvořili
            else:
                app.logger.error(f"Vlákno (ID: {run_id}): Neočekávaná RuntimeError při verifikaci dávky: {e}", exc_info=True)
                # Označit tyto emaily jako neznámé
                batch_results = [{
                    "email": email, "is_valid": None, "status_code": "thread_error",
                    "message": f"Chyba ve vlákně: {str(e)}", "is_catchall": False,
                    "verification_steps": []
                } for email in batch_to_process]
        except Exception as e:
            app.logger.error(f"Vlákno (ID: {run_id}): Chyba při verifikaci dávky: {e}", exc_info=True)
            batch_results = [{ # Označit jako chyba pro tuto dávku
                    "email": email_in_batch, "is_valid": None, "status_code": "batch_processing_error",
                    "message": f"Chyba zpracování dávky: {str(e)}", "is_catchall": False,
                    "verification_steps": []
            } for email_in_batch in batch_to_process]


        with verification_lock:
            if current_verification_state.get('verification_run_id') != run_id: # Znovu zkontrolovat, zda mezitím nebyl spuštěn nový běh
                app.logger.info(f"Vlákno (ID: {run_id}): Nový běh byl spuštěn, zatímco toto vlákno běželo. Ukončuji starý běh.")
                break # Ukončit zpracování této (staré) dávky

            for result in batch_results:
                email = result['email']
                current_verification_state['results'][email] = result
                current_verification_state['processed_emails'] += 1

                if result.get('is_valid') is True:
                    if result.get('is_catchall'):
                        current_verification_state['probable_emails'] += 1
                        domain = email.split('@')[-1]
                        current_verification_state['accept_all_domains_summary'][domain] = \
                            current_verification_state['accept_all_domains_summary'].get(domain, 0) + 1
                    else:
                        current_verification_state['valid_emails'] += 1
                elif result.get('is_valid') is False:
                    current_verification_state['invalid_emails'] += 1
                else: # is_valid is None (unknown, timeout, error)
                    current_verification_state['unknown_emails'] += 1
                
                # Přidání jednoduchého logu pro frontend
                log_status = 'success' if result.get('is_valid') else ('warning' if result.get('is_catchall') else 'error')
                current_verification_state['verification_log'].append({
                    "timestamp": datetime.now().isoformat(),
                    "status": log_status,
                    "action": f"Ověřen email: {email}",
                    "details": f"Výsledek: {result.get('status_code', 'N/A')} - {result.get('message', 'N/A')}"
                })
                # Udržet log přiměřeně krátký pro frontend
                if len(current_verification_state['verification_log']) > 100:
                    current_verification_state['verification_log'] = current_verification_state['verification_log'][-50:]

    # Konec smyčky (všechny dávky zpracovány nebo přerušeno)
    with verification_lock:
        if current_verification_state.get('verification_run_id') == run_id: # Pouze pokud je to stále aktuální běh
            if current_verification_state['status'] == 'verifying': # Pokud nebyl mezitím změněn (např. na 'stopped')
                current_verification_state['status'] = 'completed'
                app.logger.info(f"Vlákno (ID: {run_id}): Hromadná verifikace dokončena.")
                # Uložení výsledků
                save_verification_results(run_id) # Předat run_id pro konzistenci
            elif current_verification_state['status'] == 'stopped':
                 app.logger.info(f"Vlákno (ID: {run_id}): Hromadná verifikace byla zastavena, ukládám částečné výsledky.")
                 save_verification_results(run_id)
        else:
            app.logger.info(f"Vlákno (ID: {run_id}): Běh byl přerušen novým spuštěním. Výsledky pro tento starý běh nebudou uloženy centrálně.")

        if current_verification_state.get('verification_run_id') == run_id:
            current_verification_state['is_thread_active'] = False # Uvolnit flag až na úplném konci


def save_verification_results(run_id_of_save):
    """Uloží výsledky verifikace do CSV souboru."""
    # Tato funkce je volána s aktivním zámkem `verification_lock` z `run_bulk_verification_in_thread`
    # nebo by měla získat zámek, pokud je volána odjinud. Pro jednoduchost předpokládáme, že zámek je držen.
    
    if current_verification_state.get('verification_run_id') != run_id_of_save:
        app.logger.warning(f"Pokus o uložení výsledků pro neaktuální běh (ID: {run_id_of_save}). Aktuální ID: {current_verification_state.get('verification_run_id')}. Ukládání přeskočeno.")
        return

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    # Použít run_id v názvu souboru pro jednoznačnost
    result_filename = f"verification_results_{run_id_of_save or timestamp}.csv"
    result_filepath = Path(app.config['RESULTS_FOLDER']) / result_filename

    try:
        with open(result_filepath, 'w', newline='', encoding='utf-8-sig') as f: # utf-8-sig pro Excel BOM
            fieldnames = ['Email', 'Status', 'SMTP Code', 'SMTP Message', 'Is Catchall', 'MX Record', 'Server IP']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            for email, result_data in current_verification_state.get('results', {}).items():
                status_str = "Neznámý"
                is_catchall_str = "Ne"

                if result_data.get('is_valid') is True:
                    if result_data.get('is_catchall'):
                        status_str = "Pravděpodobně validní"
                        is_catchall_str = "Ano"
                    else:
                        status_str = "Validní"
                elif result_data.get('is_valid') is False:
                    status_str = "Nevalidní"
                
                writer.writerow({
                    'Email': email,
                    'Status': status_str,
                    'SMTP Code': result_data.get('smtp_code_internal', result_data.get('status_code', 'N/A')),
                    'SMTP Message': result_data.get('message', 'N/A'),
                    'Is Catchall': is_catchall_str,
                    'MX Record': result_data.get('mx_record', 'N/A'),
                    'Server IP': result_data.get('server_ip', 'N/A')
                })
        
        current_verification_state['result_filepath'] = str(result_filepath)
        app.logger.info(f"Výsledky verifikace (ID: {run_id_of_save}) uloženy do '{result_filepath}'.")
    except Exception as e:
        app.logger.error(f"Chyba při ukládání výsledků (ID: {run_id_of_save}) do CSV: {e}", exc_info=True)
        current_verification_state['error_message'] = f"Chyba při ukládání výsledků: {str(e)}"
        if current_verification_state['status'] not in ['error', 'stopped']: # Nepřepisovat pokud už je chyba
            current_verification_state['status'] = 'error'


@app.route('/start_verification', methods=['GET']) # Frontend volá GET
def start_verification_route():
    """Spustí hromadnou verifikaci emailů."""
    global bulk_verification_thread
    with verification_lock:
        if current_verification_state['status'] not in ['ready_to_verify', 'stopped', 'completed', 'error', 'idle']:
             app.logger.warning(f"API /start_verification: Pokus o spuštění, když je stav '{current_verification_state['status']}'.")
             return jsonify({'error': 'Verifikace již běží nebo není připravena.'}), 400
        
        if not current_verification_state.get('emails_to_verify'):
            return jsonify({'error': 'Nejprve nahrajte CSV a vyberte sloupec s emaily.'}), 400

        # Pokud existuje staré vlákno a stále běží (což by nemělo být, pokud je stav OK)
        if bulk_verification_thread and bulk_verification_thread.is_alive():
            app.logger.warning("API /start_verification: Staré vlákno pro verifikaci stále běží. Pokus o jeho zastavení.")
            current_verification_state['stop_requested'] = True # Signal pro staré vlákno
            # Počkat chvíli, než se staré vlákno ukončí (v reálu by to chtělo robustnější join s timeoutem)
            # Pro jednoduchost zde nepoužijeme join, aby API odpovědělo rychle
            # Staré vlákno by mělo detekovat změnu run_id nebo stop_requested

        # Resetovat relevantní části stavu pro nový běh
        current_verification_state['status'] = 'verifying'
        current_verification_state['error_message'] = None
        current_verification_state['processed_emails'] = 0
        current_verification_state['valid_emails'] = 0
        current_verification_state['invalid_emails'] = 0
        current_verification_state['probable_emails'] = 0
        current_verification_state['unknown_emails'] = 0
        current_verification_state['results'] = {}
        current_verification_state['verification_log'] = []
        current_verification_state['start_time'] = datetime.now().isoformat()
        current_verification_state['last_activity_time'] = time.time()
        current_verification_state['result_filepath'] = None
        current_verification_state['accept_all_domains_summary'] = {}
        current_verification_state['stop_requested'] = False
        current_verification_state['verification_run_id'] = int(time.time() * 1000) # Unikátní ID pro tento běh
        current_verification_state['is_thread_active'] = False # Tento flag se nastaví na True ve vlákně

        # Vypočítat počet dávek pro UI (může se lišit od interního dávkování EmailVerifieru)
        app_batch_size_for_ui = 20 # Stejná jako v run_bulk_verification_in_thread
        current_verification_state['total_batches'] = (current_verification_state['total_emails'] + app_batch_size_for_ui - 1) // app_batch_size_for_ui


        app.logger.info(f"API /start_verification: Spouštění nového běhu verifikace s ID: {current_verification_state['verification_run_id']}.")
        # Spuštění verifikace v samostatném vlákně
        bulk_verification_thread = threading.Thread(target=run_bulk_verification_in_thread, name="BulkVerifyThread")
        bulk_verification_thread.daemon = True # Aby se vlákno ukončilo s hlavní aplikací
        bulk_verification_thread.start()

    return jsonify({'status': 'verifying', 'message': 'Verifikace byla spuštěna.'})


@app.route('/status', methods=['GET'])
def status_route():
    """Vrátí aktuální stav hromadné verifikace."""
    with verification_lock:
        # Pokud vlákno skončilo (neočekávaně nebo normálně) a stav nebyl aktualizován
        if current_verification_state.get('is_thread_active') and \
           bulk_verification_thread and not bulk_verification_thread.is_alive() and \
           current_verification_state['status'] == 'verifying':
            app.logger.warning("Stav: Vlákno verifikace již neběží, ale stav je stále 'verifying'. Aktualizuji na 'error' nebo 'completed'.")
            # Zde by se mohla zkontrolovat, zda jsou všechny emaily zpracovány, aby se určilo 'completed' vs 'error'
            if current_verification_state['processed_emails'] >= current_verification_state['total_emails']:
                 current_verification_state['status'] = 'completed'
                 if not current_verification_state.get('result_filepath'): # Pokud soubor nebyl uložen
                     save_verification_results(current_verification_state.get('verification_run_id'))
            else:
                 current_verification_state['status'] = 'error'
                 current_verification_state['error_message'] = 'Proces verifikace byl neočekávaně ukončen.'
            current_verification_state['is_thread_active'] = False


        # Připravit data pro frontend (včetně logu)
        status_payload = {
            key: val for key, val in current_verification_state.items()
            if key not in ['emails_to_verify', 'results'] # Neposílat celé seznamy/slovníky, pokud nejsou potřeba
        }
        # Přidat přehled domén
        status_payload['accept_all_details'] = {
            "count": sum(current_verification_state.get('accept_all_domains_summary', {}).values()),
            "domains": [{"domain": d, "count": c} for d,c in sorted(current_verification_state.get('accept_all_domains_summary', {}).items(), key=lambda item: item[1], reverse=True)[:10]]
        }
        # Posledních N logů
        status_payload['verification_log_batch'] = current_verification_state.get('verification_log', [])[-20:]


    return jsonify(status_payload)


@app.route('/stop_verification', methods=['POST'])
def stop_verification_route():
    """Zastaví probíhající hromadnou verifikaci."""
    global bulk_verification_thread
    stopped_successfully = False
    message = "Žádná aktivní verifikace k zastavení."

    with verification_lock:
        if current_verification_state['status'] == 'verifying' and \
           current_verification_state.get('is_thread_active', False) and \
           bulk_verification_thread and bulk_verification_thread.is_alive():
            
            app.logger.info(f"API /stop_verification: Požadavek na zastavení verifikace (ID: {current_verification_state['verification_run_id']}).")
            current_verification_state['stop_requested'] = True
            current_verification_state['status'] = 'stopping' # Indikace, že se zastavuje
            message = "Požadavek na zastavení odeslán. Čekání na dokončení aktuální dávky a uložení výsledků."
            # Nečekáme zde na join vlákna, aby API odpovědělo rychle.
            # Vlákno by se mělo samo ukončit a uložit výsledky.
            # Status endpoint pak ukáže finální 'stopped' stav.
            stopped_successfully = True # Indikuje, že byl signál odeslán běžícímu procesu
        elif current_verification_state['status'] == 'verifying':
            # Vlákno už možná neběží, ale stav se ještě neaktualizoval
            app.logger.warning(f"API /stop_verification: Stav je 'verifying', ale vlákno neběží nebo není aktivní. Nastavuji stav na 'stopped'.")
            current_verification_state['status'] = 'stopped'
            save_verification_results(current_verification_state.get('verification_run_id'))
            message = "Verifikace byla zastavena (vlákno již neběželo)."
            current_verification_state['is_thread_active'] = False


    if stopped_successfully:
        return jsonify({'status': 'stopping', 'message': message})
    else:
        # Vrátit aktuální stav, pokud se nic nezastavovalo
        with verification_lock:
            current_status = current_verification_state['status']
            filepath_to_return = current_verification_state.get('result_filepath')

        return jsonify({
            'status': current_status, # 'stopped', 'completed', 'error', 'idle'
            'message': message,
            'filepath': filepath_to_return # Pokud již existuje soubor
        })


@app.route('/download', methods=['GET'])
def download_results_route():
    """Umožní stažení výsledného CSV souboru."""
    # Frontend posílá filepath jako query parametr
    filepath_param = request.args.get('filepath')
    
    # Pro bezpečnost bychom měli ověřit, že soubor je v našem RESULTS_FOLDER
    # a normalizovat cestu, abychom zabránili path traversal.
    if not filepath_param:
        return jsonify({'error': 'Chybí parametr filepath'}), 400

    # Normalizace a kontrola cesty
    results_folder_abs = Path(app.config['RESULTS_FOLDER']).resolve()
    requested_file_abs = (results_folder_abs / Path(filepath_param).name).resolve() # Použít jen basename

    if not requested_file_abs.is_file() or requested_file_abs.parent != results_folder_abs:
        app.logger.warning(f"API /download: Pokus o stažení nevalidního souboru: '{filepath_param}' (Resolved: '{requested_file_abs}')")
        return jsonify({'error': 'Soubor nenalezen nebo neplatná cesta'}), 404

    app.logger.info(f"API /download: Poskytování souboru '{requested_file_abs}' ke stažení.")
    return send_file(requested_file_abs, as_attachment=True)


# --- Spuštění aplikace ---
if __name__ == '__main__':
    # Pro vývoj je `debug=True` v pořádku.
    # Flaskův vývojový server je synchronní a jednoprocesový.
    # Pro `async` operace v `EmailVerifier` používané přes `asyncio.run()`
    # a hromadnou verifikaci ve vlákně by to mělo fungovat, ale není to
    # tak efektivní jako s ASGI serverem (např. Uvicorn).
    app.run(debug=True, host="0.0.0.0", port=5000)
    # Pro produkci: Gunicorn + Uvicorn worker (pro async Flask) nebo jiný WSGI/ASGI server.
    # např. gunicorn -w 4 -k uvicorn.workers.UvicornWorker app:app