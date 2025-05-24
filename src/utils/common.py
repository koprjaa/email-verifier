import logging
import json
import csv
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Tuple

def setup_logging(log_level=logging.INFO) -> logging.Logger:
    """
    Nastavení logování s rotací souborů.
    
    Args:
        log_level: Úroveň logování (default: INFO)
        
    Returns:
        logging.Logger: Instance loggeru
    """
    # Vytvoření adresáře pro logy
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    
    # Nastavení formátu logu
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Handler pro soubor
    file_handler = logging.FileHandler(
        log_dir / "email_verifier.log",
        encoding='utf-8'
    )
    file_handler.setFormatter(formatter)
    
    # Handler pro konzoli
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    
    # Vytvoření loggeru
    logger = logging.getLogger("EmailVerifier")
    logger.setLevel(log_level)
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger

def load_config(config_path: str = "config.json") -> Dict[str, Any]:
    """
    Načtení konfiguračního souboru.
    
    Args:
        config_path: Cesta ke konfiguračnímu souboru
        
    Returns:
        Dict[str, Any]: Konfigurační parametry
    """
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)
            
        # Validace povinných parametrů
        required_params = [
            "timeout", "max_workers", "catchall_test",
            "connect_port", "retry_attempts", "retry_delay",
            "rate_limit_delay", "check_disposable", "check_catchall",
            "batch_size", "max_concurrent_domains", "sender_emails"
        ]
        
        missing_params = [param for param in required_params if param not in config]
        if missing_params:
            raise ValueError(f"Chybí povinné parametry v konfiguraci: {', '.join(missing_params)}")
            
        return config
        
    except FileNotFoundError:
        raise FileNotFoundError(f"Konfigurační soubor {config_path} nebyl nalezen")
    except json.JSONDecodeError:
        raise ValueError(f"Nevalidní formát konfiguračního souboru {config_path}")
    except Exception as e:
        raise Exception(f"Chyba při načítání konfigurace: {str(e)}")

def export_results(valid_emails: List[Tuple[str, int, str]], invalid_emails: List[Tuple[str, int, str]], 
                  unknown_emails: List[Tuple[str, int, str]], output_dir: str = "results") -> None:
    """Export výsledků do různých formátů"""
    output_path = Path(output_dir)
    output_path.mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Export do CSV
    csv_path = output_path / f"verification_results_{timestamp}.csv"
    with open(csv_path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Email', 'Status', 'SMTP kód', 'SMTP zpráva'])
        for email, code, message in valid_emails:
            writer.writerow([email, 'Validní', code, message])
        for email, code, message in invalid_emails:
            writer.writerow([email, 'Nevalidní', code, message])
        for email, code, message in unknown_emails:
            writer.writerow([email, 'Neznámý', code, message])

    # Export do JSON
    json_path = output_path / f"verification_results_{timestamp}.json"
    results = {
        'valid': [{'email': email, 'code': code, 'message': message} for email, code, message in valid_emails],
        'invalid': [{'email': email, 'code': code, 'message': message} for email, code, message in invalid_emails],
        'unknown': [{'email': email, 'code': code, 'message': message} for email, code, message in unknown_emails],
        'timestamp': timestamp,
        'total_processed': len(valid_emails) + len(invalid_emails) + len(unknown_emails)
    }
    with open(json_path, 'w') as f:
        json.dump(results, f, indent=4) 