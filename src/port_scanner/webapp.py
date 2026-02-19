from __future__ import annotations

from flask import Flask, request, render_template_string
from port_scanner.cli import parse_ports, run_scan
from port_scanner.scanner import resolve_target

app = Flask(__name__)

PAGE = """
<!doctype html>
<html lang="pt-br">
<head>
  <meta charset="utf-8">
  <title>Port Scanner (Local)</title>
  <style>
    body { font-family: Arial, sans-serif; max-width: 900px; margin: 40px auto; padding: 0 16px; }
    input { padding: 10px; width: 100%; margin: 6px 0 14px; }
    button { padding: 10px 16px; cursor: pointer; }
    .row { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
    .box { border: 1px solid #ddd; border-radius: 10px; padding: 16px; }
    .warn { background: #fff7e6; border: 1px solid #ffd28a; padding: 12px; border-radius: 10px; }
    code { background: #f6f8fa; padding: 2px 6px; border-radius: 6px; }
    table { width: 100%; border-collapse: collapse; margin-top: 12px; }
    th, td { border-bottom: 1px solid #eee; text-align: left; padding: 8px; }
  </style>
</head>
<body>
  <h1>Port Scanner (Local)</h1>

  <div class="warn">
    <strong>Uso autorizado apenas.</strong>
    Use somente em alvos que você possui ou tem permissão explícita para testar.
  </div>

  <div class="box" style="margin-top: 16px;">
    <form method="POST">
      <label>Target (IP ou domínio)</label>
      <input name="target" placeholder="ex: 127.0.0.1 ou example.com" value="{{ target or '' }}" required>

      <div class="row">
        <div>
          <label>Ports (ex: <code>22,80,443</code> ou <code>1-1024</code>)</label>
          <input name="ports" placeholder="vazio = portas comuns" value="{{ ports or '' }}">
        </div>
        <div>
          <label>Timeout (segundos)</label>
          <input name="timeout" type="number" step="0.1" value="{{ timeout or 0.6 }}">
        </div>
      </div>

      <div class="row">
        <div>
          <label>Workers (concorrência)</label>
          <input name="workers" type="number" value="{{ workers or 200 }}">
        </div>
        <div>
          <label>Banner grabbing (leve)</label>
          <input name="banner" type="checkbox" {% if banner %}checked{% endif %}>
        </div>
      </div>

      <button type="submit">Scan</button>
    </form>
  </div>

  {% if error %}
    <p style="color:#b00020;"><strong>Erro:</strong> {{ error }}</p>
  {% endif %}

  {% if result %}
    <div class="box" style="margin-top: 16px;">
      <p><strong>Target:</strong> {{ result.target }} ({{ result.ip }})</p>
      <p><strong>Portas escaneadas:</strong> {{ result.scanned }} | <strong>Abertas:</strong> {{ result.open_count }}</p>

      {% if result.open_ports %}
        <table>
          <thead><tr><th>Porta</th><th>Banner</th></tr></thead>
          <tbody>
            {% for p in result.open_ports %}
              <tr>
                <td>{{ p.port }}</td>
                <td>{{ p.banner or '' }}</td>
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


@app.route("/", methods=["GET", "POST"])
def index():
    error = None
    result = None

    target = ""
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

            ip = resolve_target(target)
            ports_list = parse_ports(ports if ports else None)

            results = run_scan(ip=ip, ports=ports_list, timeout=timeout, workers=workers, banner=banner)
            open_ports = [r for r in results if r.is_open]

            result = {
                "target": target,
                "ip": ip,
                "scanned": len(ports_list),
                "open_count": len(open_ports),
                "open_ports": open_ports,
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


def main():
    # Local only. If you want LAN access, change host="0.0.0.0"
    app.run(host="127.0.0.1", port=5000, debug=False)
