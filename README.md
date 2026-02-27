# Python Port Scanner (Lab / Authorized Use)

## 🇧🇷 Português

Scanner TCP de portas para fins educacionais, com:
- CLI para varredura rápida
- Exportação para CSV/JSON
- Web app local em Flask

### Uso autorizado apenas
Use **somente** em sistemas que você possui ou para os quais recebeu permissão explícita.

### Requisitos
- Python 3.10+

### Instalação
No diretório raiz do projeto:

```bash
python -m venv .venv
# Windows (PowerShell)
.venv\Scripts\Activate.ps1

pip install -e .
```

### Executando pela CLI
Após instalar com `pip install -e .`, use:

```bash
portscan --target 127.0.0.1
```

Exemplos:

```bash
portscan --target 127.0.0.1 --ports 1-1024 --workers 100
portscan --target example.com --ports "22,80,443" --timeout 0.8 --out-csv output/results.csv
portscan --target 192.168.0.10 --banner --out-json output/results.json
```

### Opções da CLI
- `--target` (obrigatório): IP ou domínio (ex.: `192.168.0.10`, `example.com`)
- `--ports`: lista (`"22,80,443"`) ou faixa (`"1-1024"`); padrão: `COMMON_PORTS`
- `--timeout`: timeout do socket em segundos (padrão: `0.6`)
- `--workers`: concorrência máxima (padrão: `200`)
- `--banner`: tenta banner grabbing simples
- `--out-csv`: salva resultado em CSV
- `--out-json`: salva resultado em JSON

### Web app local (Flask)
Suba a interface web local:

```bash
portscan-web
```

Abra no navegador:

```text
http://127.0.0.1:5000
```

Na interface web você pode:
- configurar target, portas, timeout, workers e banner
- visualizar portas abertas e serviço provável
- baixar o último scan em CSV/JSON

### Saída dos resultados
- CLI imprime resumo e portas abertas no terminal
- CSV/JSON (CLI): inclui resultados de portas abertas e fechadas
- CSV/JSON (Web): inclui metadados + linhas completas do scan

### Testes
Executar testes:

```bash
pytest -q
```

Atualmente os testes cobrem o parser de portas (`parse_ports`).

---

## 🇺🇸 English

Educational TCP port scanner with:
- CLI for quick scanning
- CSV/JSON export
- Local Flask web app

### Authorized use only
Use **only** on systems you own or have explicit permission to test.

### Requirements
- Python 3.10+

### Installation
From the project root:

```bash
python -m venv .venv
# Windows (PowerShell)
.venv\Scripts\Activate.ps1

pip install -e .
```

### Run via CLI
After installing with `pip install -e .`, run:

```bash
portscan --target 127.0.0.1
```

Examples:

```bash
portscan --target 127.0.0.1 --ports 1-1024 --workers 100
portscan --target example.com --ports "22,80,443" --timeout 0.8 --out-csv output/results.csv
portscan --target 192.168.0.10 --banner --out-json output/results.json
```

### CLI options
- `--target` (required): IP or domain (e.g., `192.168.0.10`, `example.com`)
- `--ports`: list (`"22,80,443"`) or range (`"1-1024"`); default: `COMMON_PORTS`
- `--timeout`: socket timeout in seconds (default: `0.6`)
- `--workers`: max concurrency (default: `200`)
- `--banner`: attempts light banner grabbing
- `--out-csv`: saves results to CSV
- `--out-json`: saves results to JSON

### Local web app (Flask)
Start the local web interface:

```bash
portscan-web
```

Open in browser:

```text
http://127.0.0.1:5000
```

In the web interface you can:
- configure target, ports, timeout, workers, and banner
- view open ports and likely service
- download the latest scan as CSV/JSON

### Output
- CLI prints summary and open ports in terminal
- CSV/JSON (CLI): includes open and closed ports
- CSV/JSON (Web): includes metadata + full scan rows

### Tests
Run tests with:

```bash
pytest -q
```

Current tests cover the port parser (`parse_ports`).

---

## Scripts
Defined in `pyproject.toml`:
- `portscan` → `port_scanner.cli:main`
- `portscan-web` → `port_scanner.webapp:main`

## Project structure (summary)
```text
src/port_scanner/
  cli.py
  scanner.py
  output.py
  webapp.py
  ports.py
  services.py
tests/
  test_ports.py
```


