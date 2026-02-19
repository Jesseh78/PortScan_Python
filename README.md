# Python Port Scanner (Lab/Authorized Use)

Educational TCP connect port scanner written in Python.

## Authorized use only
Use only on systems you own or have explicit permission to test.

## Run
From repo root:

```bash
python -m src.port_scanner.cli --target 127.0.0.1
python -m src.port_scanner.cli --target 127.0.0.1 --ports 1-1024 --workers 100
python -m src.port_scanner.cli --target example.com --ports "22,80,443" --timeout 0.8 --out-csv output/results.csv
python -m src.port_scanner.cli --target 192.168.0.10 --banner --out-json output/results.json


