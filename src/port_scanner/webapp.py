from __future__ import annotations

import csv
import json
from io import StringIO, BytesIO
from dataclasses import asdict
from typing import Any, Dict, List

from flask import Flask, request, render_template_string, send_file, redirect, url_for

from port_scanner.cli import parse_ports, run_scan
from port_scanner.scanner import resolve_target, ScanResult
from port_scanner.services import COMMON_SERVICES

app = Flask(__name__)

# Guarda o último scan em memória (por simplicidade: global).
# Para multi-usuário real, use session/redis/db.
LAST_SCAN: Dict[str, Any] | None = None

PAGE = """
<!doctype html>
<html lang="pt-br">
<head>
  <meta charset="utf-8">
  <title>Port Scanner (Local)</title>
  <style>
    body { font-family: Arial, sans-serif; max-width: 980px; margin: 40px auto; padding: 0 16px; }
    input { padding: 10px; width: 100%; margin: 6px 0 14px; box-sizing: border-box; }
    button, a.btn { padding: 10px 16px; cursor: pointer; display:inline-block; text-decoration:none; border:1px solid #ccc; border-radius:8px; background:#f7f7f7; color:#000; }
    button:hover, a.btn:hover { background:#eee; }
    .row { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
    .box { border: 1px solid #ddd; border-radius: 10px; padding: 16px; background: #fff; }
    .warn { background: #fff7e6; border: 1px solid #ffd28a; padding: 12px; border-radius: 10px; }
    code { background: #f6f8fa; padding: 2px 6px; border-radius: 6px; }
    table { width: 100%; border-collapse: collapse; margin-top: 12px; }
    th, td { border-bottom: 1px solid #eee; text-align: left; padding: 8px; vertical-align: top; }
    th { background: #fafafa; }
    .muted { color: #666; font-size: 0.95em; }
    .error { color:#b00020; margin-top: 12px; }
    .pill { display:inline-block; padding: 3px 8px; border-radius: 999px; background:#f2f2f2; font-size: 0.85em; }
    .actions { margin-top: 10px; display:flex; gap:10px; flex-wrap:wrap; }
  </style>
</head>
<body>
  <h1>Port Scanner (Local)</h1>

  <div class="warn">
    <strong>Uso autorizado apenas.</strong>
    Use somente em alvos que você possui ou tem permissão explícita para testar.
    <div class="muted" style="margin-top:6px;">
      Dica: comece com <code>127.0.0.1</code> ou sua VM no VirtualBox.
    </div>
  </div>

  <div class="box" style="margin-top: 16px;">
    <form method="POST">
      <label><strong>Target</strong> (IP ou domínio)</label>
      <input name="target" placeholder="ex: 127.0.0.1 ou example.com" value="{{ target or '' }}" required>

      <div class="row">
        <div>
          <label><strong>Ports</strong> (ex: <code>22,80,443</code> ou <code>1-1024</code>)</label>
          <input name="ports" placeholder="vazio = portas comuns" value="{{ ports or '' }}">
        </div>
        <div>
          <label><strong>Timeout</strong> (segundos)</label>
          <input name="timeout" type="number" step="0.1" min="0.1" value="{{ timeout }}">
        </div>
      </div>

      <div class="row">
        <div>
          <label><strong>Workers</strong> (concorrência)</label>
          <input name="workers" type="number" min="1" max="2000" value="{{ workers }}">
          <div class="muted">Se travar, reduza para 50–100.</div>
        </div>
        <div>
          <label><strong>Banner grabbing</strong> (leve)</label><br>
          <input name="banner" type="checkbox" {% if banner %}checked{% endif %}>
          <span class="muted">Tenta ler um banner simples (nem sempre funciona).</span>
        </div>
      </div>

      <button type="submit">Scan</button>
    </form>
  </div>

  {% if error %}
    <div class="error"><strong>Erro:</strong> {{ error }}</div>
  {% endif %}

  {% if result %}
    <div class="box" style="margin-top: 16px;">
      <p>
        <strong>Target:</strong> {{ result.target }} <span class="pill">{{ result.ip }}</span>
      </p>
      <p>
        <strong>Portas escaneadas:</strong> {{ result.scanned }}
        &nbsp;|&nbsp;
        <strong>Abertas:</strong> {{ result.open_count }}
      </p>

      <div class="actions">
        <a class="btn" href="{{ url_for('download_csv') }}">Baixar CSV</a>
        <a class="btn" href="{{ url_for('download_json') }}">Baixar JSON</a>
      </div>

      {% if result.open_ports %}
        <table>
          <thead>
            <tr>
              <th style="width: 90px;">Porta</th>
              <th style="width: 180px;">Serviço</th>
              <th>Banner</th>
            </tr>
          </thead>
          <tbody>
            {% for p in result.open_ports %}
              <tr>
                <td>{{ p.port }}</td>
                <td>{{ p.service }}</td>
                <td>{{ p.banner or "" }}</td>
              </tr>
            {% endfor %}
          </tbody>
        </table>
      {% else %}
        <p>Nenhuma porta aberta encontrada com esses parâmetros.</p>
      {% endif %}
    </div>
  {% endif %}
</body>
</html>
"""


def _validate_inputs(timeout: float, workers: int) -> None:
    if timeout < 0.1 or timeout > 10:
        raise ValueError("Timeout inválido. Use um valor entre 0.1 e 10 segundos.")
    if workers < 1 or workers > 2000:
        raise ValueError("Workers inválido. Use entre 1 e 2000.")


def _make_export_payload(target: str, ip: str, ports_list: List[int], results: List[ScanResult]) -> Dict[str, Any]:
    """
    Guarda payload com resultados completos (abertas e fechadas) para export.
    """
    rows = []
    for r in results:
        rows.append({
            "target": target,
            "ip": ip,
            "port": r.port,
            "service": COMMON_SERVICES.get(r.port, "Unknown"),
            "is_open": r.is_open,
            "banner": r.banner,
            "error": r.error,
        })

    open_ports_ui = []
    for r in results:
        if r.is_open:
            open_ports_ui.append({
                "port": r.port,
                "service": COMMON_SERVICES.get(r.port, "Unknown"),
                "banner": r.banner,
            })

    return {
        "meta": {
            "target": target,
            "ip": ip,
            "scanned": len(ports_list),
            "open_count": sum(1 for x in results if x.is_open),
        },
        "rows": rows,
        "open_ports_ui": open_ports_ui,
    }


def _export_csv_bytes(rows: List[Dict[str, Any]]) -> bytes:
    sio = StringIO()
    fieldnames = ["target", "ip", "port", "service", "is_open", "banner", "error"]
    writer = csv.DictWriter(sio, fieldnames=fieldnames)
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    return sio.getvalue().encode("utf-8")


def _export_json_bytes(payload: Dict[str, Any]) -> bytes:
    return json.dumps(payload, indent=2, ensure_ascii=False).encode("utf-8")


@app.route("/", methods=["GET", "POST"])
def index():
    global LAST_SCAN

    error = None
    result = None

    # defaults
    target = "127.0.0.1"
    ports = ""
    timeout = 0.6
    workers = 200
    banner = False

    if request.method == "POST":
        try:
            target = request.form.get("target", "").strip()
            ports = request.form.get("ports", "").strip()
            timeout = float(request.form.get("timeout", "0.6"))
            workers = int(request.form.get("workers", "200"))
            banner = request.form.get("banner") == "on"

            _validate_inputs(timeout=timeout, workers=workers)

            ip = resolve_target(target)
            ports_list = parse_ports(ports if ports else None)

            results = run_scan(
                ip=ip,
                ports=ports_list,
                timeout=timeout,
                workers=workers,
                banner=banner
            )

            export_payload = _make_export_payload(target, ip, ports_list, results)
            LAST_SCAN = export_payload  # <- salva último scan em memória

            result = {
                "target": export_payload["meta"]["target"],
                "ip": export_payload["meta"]["ip"],
                "scanned": export_payload["meta"]["scanned"],
                "open_count": export_payload["meta"]["open_count"],
                "open_ports": export_payload["open_ports_ui"],
            }
        except Exception as e:
            error = str(e)

    return render_template_string(
        PAGE,
        error=error,
        result=result,
        target=target,
        ports=ports,
        timeout=timeout,
        workers=workers,
        banner=banner,
    )


@app.route("/download/csv", methods=["GET"])
def download_csv():
    if not LAST_SCAN:
        return redirect(url_for("index"))

    csv_bytes = _export_csv_bytes(LAST_SCAN["rows"])
    bio = BytesIO(csv_bytes)
    bio.seek(0)

    filename = "portscan_results.csv"
    return send_file(
        bio,
        mimetype="text/csv",
        as_attachment=True,
        download_name=filename
    )


@app.route("/download/json", methods=["GET"])
def download_json():
    if not LAST_SCAN:
        return redirect(url_for("index"))

    payload_bytes = _export_json_bytes(LAST_SCAN)
    bio = BytesIO(payload_bytes)
    bio.seek(0)

    filename = "portscan_results.json"
    return send_file(
        bio,
        mimetype="application/json",
        as_attachment=True,
        download_name=filename
    )


def main():
    app.run(host="127.0.0.1", port=5000, debug=False)


if __name__ == "__main__":
    main()