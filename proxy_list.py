#!/usr/bin/env python3
"""
Recolector unificado de proxies SOCKS5 gratuitos.

Reúne los listados de geonode.com, proxydb.net y spys.one en un único archivo
de texto, agrupados por fuente:

    # Geonode
    socks5 <IP> <Puerto>
    ...

    # ProxyDB
    socks5 <IP> <Puerto>
    ...

    # Spys.one
    socks5 <IP> <Puerto>
    ...

Uso:
    python3 proxy_list.py
    python3 proxy_list.py --verify
    python3 proxy_list.py --verify -o mis_proxies.txt
"""

from __future__ import annotations

import argparse
import ipaddress
import random
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

try:
    import requests
    import urllib3
    from bs4 import BeautifulSoup
except ImportError:  # pragma: no cover
    sys.exit(
        "Faltan dependencias. Instala con:\n"
        "    pip install requests beautifulsoup4 PySocks"
    )

# Muchos proxies gratuitos devuelven un TLS interceptado: se acepta el
# certificado durante la verificación para no descartar proxies que sirven.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
)

GEONODE_URL = (
    "https://proxylist.geonode.com/api/proxy-list?protocols=socks5"
    "&filterUpTime=100&speed=fast&page=1&limit=500"
    "&sort_by=responseTime&sort_type=asc"
)
PROXYDB_URL = (
    "https://proxydb.net/?country=&protocol=socks5"
    "&sort_column_id=uptime&sort_order_desc=true"
)
SPYS_URL = "https://spys.one/en/socks-proxy-list/"

PROXYDB_TOP = 10
PROXYDB_PAGE_SIZE = 30
PROXYDB_MAX_PAGES = 20

HTTP_TIMEOUT = 20.0
HTTP_RETRIES = 3
VERIFY_TIMEOUT = 8.0
VERIFY_ATTEMPTS = 2
VERIFY_WORKERS = 50
VERIFY_URL = "https://api.ipify.org?format=json"

DEFAULT_OUTPUT = Path(__file__).resolve().with_name("proxies.txt")


# --------------------------------------------------------------------------- #
# Modelo y utilidades comunes
# --------------------------------------------------------------------------- #
@dataclass
class Proxy:
    ip: str
    port: int
    protocol: str = "socks5"
    source: str = ""

    @property
    def key(self) -> tuple[str, int]:
        return self.ip, self.port

    @property
    def line(self) -> str:
        return f"{self.protocol} {self.ip} {self.port}"


def build_url(base_url: str, **params: object) -> str:
    """Añade o reemplaza parámetros de la query de una URL."""
    parts = urlparse(base_url)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    for key, value in params.items():
        if value is None or value == "":
            query.pop(key, None)
        else:
            query[key] = value
    return urlunparse(parts._replace(query=urlencode(query)))


def make_session(referer: str, accept: str) -> requests.Session:
    session = requests.Session()
    session.headers.update({
        "User-Agent": USER_AGENT,
        "Accept": accept,
        "Accept-Language": "en-US,en;q=0.9",
        "Referer": referer,
    })
    return session


def backoff(attempt: int) -> float:
    return min(2 ** (attempt - 1), 8) + random.uniform(0, 0.5)


def valid_endpoint(ip: str, port: int) -> bool:
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return False
    return 1 <= port <= 65535


def fetch_text(
    session: requests.Session,
    url: str,
    *,
    check_cloudflare: bool = False,
) -> str | None:
    """Descarga una página de texto con reintentos."""
    last_error: Exception | None = None
    for attempt in range(1, HTTP_RETRIES + 1):
        try:
            response = session.get(url, timeout=HTTP_TIMEOUT)
            if response.status_code == 200:
                if check_cloudflare and "Just a moment" in response.text[:2000]:
                    last_error = RuntimeError("desafío de Cloudflare")
                else:
                    return response.text
            else:
                last_error = requests.HTTPError(f"HTTP {response.status_code}")
        except requests.RequestException as exc:
            last_error = exc
        if attempt < HTTP_RETRIES:
            wait = backoff(attempt)
            print(
                f"  ! reintento {attempt}/{HTTP_RETRIES - 1} "
                f"en {wait:.1f}s ({last_error})",
                file=sys.stderr,
            )
            time.sleep(wait)
    print(f"  x fallo al descargar {url}: {last_error}", file=sys.stderr)
    return None


def fetch_json(session: requests.Session, url: str) -> dict | None:
    """Descarga una página JSON con reintentos."""
    last_error: Exception | None = None
    for attempt in range(1, HTTP_RETRIES + 1):
        try:
            response = session.get(url, timeout=HTTP_TIMEOUT)
            if response.status_code == 200:
                payload = response.json()
                if payload.get("data") is None and payload.get("message"):
                    print(f"  x API: {payload['message']}", file=sys.stderr)
                    return None
                return payload
            last_error = requests.HTTPError(f"HTTP {response.status_code}")
            if 400 <= response.status_code < 500 and response.status_code != 429:
                print(
                    f"  x el API rechazó la petición: HTTP {response.status_code}",
                    file=sys.stderr,
                )
                return None
        except requests.RequestException as exc:
            last_error = exc
        except ValueError as exc:
            last_error = exc
        if attempt < HTTP_RETRIES:
            wait = backoff(attempt)
            print(
                f"  ! reintento {attempt}/{HTTP_RETRIES - 1} "
                f"en {wait:.1f}s ({last_error})",
                file=sys.stderr,
            )
            time.sleep(wait)
    print(f"  x fallo al descargar {url}: {last_error}", file=sys.stderr)
    return None


# --------------------------------------------------------------------------- #
# Geonode (API JSON)
# --------------------------------------------------------------------------- #
def build_geonode_proxy(entry: dict) -> Proxy | None:
    ip = str(entry.get("ip", "")).strip()

    raw_port = entry.get("port")
    ports = raw_port if isinstance(raw_port, list) else [raw_port]
    port = None
    for candidate in ports:
        try:
            value = int(str(candidate).strip())
        except (TypeError, ValueError):
            continue
        if 1 <= value <= 65535:
            port = value
            break
    if port is None or not valid_endpoint(ip, port):
        return None

    protocols = entry.get("protocols") or []
    if isinstance(protocols, str):
        protocols = [protocols]
    protocols = [str(value).lower() for value in protocols]
    if protocols and "socks5" not in protocols:
        return None

    return Proxy(ip=ip, port=port, protocol="socks5", source="Geonode")


def fetch_geonode() -> list[Proxy]:
    session = make_session(
        "https://proxylist.geonode.com/",
        "application/json, text/plain, */*",
    )
    proxies: list[Proxy] = []
    total: int | None = None
    page = 1

    while True:
        print(f"[Geonode] descargando página {page} ...", file=sys.stderr)
        payload = fetch_json(session, build_url(GEONODE_URL, page=page))
        if payload is None:
            break

        entries = payload.get("data") or []
        if not entries:
            break

        raw_total = payload.get("total", total)
        try:
            total = int(raw_total)
        except (TypeError, ValueError):
            total = None

        new = 0
        for entry in entries:
            proxy = build_geonode_proxy(entry)
            if proxy is not None:
                proxies.append(proxy)
                new += 1
        print(
            f"  {len(entries)} entradas, {new} válidas "
            f"(acumuladas {len(proxies)})",
            file=sys.stderr,
        )

        if total is not None and len(proxies) >= total:
            break
        page += 1
        time.sleep(0.5 + random.uniform(0, 0.2))

    return proxies


# --------------------------------------------------------------------------- #
# ProxyDB (HTML)
# --------------------------------------------------------------------------- #
RE_PROXYDB_TOTAL = re.compile(
    r"Showing\s+\d+\s+to\s+\d+\s+of\s+([\d,]+)\s+total proxies"
)


def parse_proxydb_total(html: str) -> int | None:
    match = RE_PROXYDB_TOTAL.search(html)
    return int(match.group(1).replace(",", "")) if match else None


def parse_proxydb_rows(html: str) -> list[Proxy]:
    soup = BeautifulSoup(html, "html.parser")
    table = soup.find("table")
    if table is None:
        return []

    proxies: list[Proxy] = []
    for row in table.select("tbody tr"):
        cells = row.find_all("td")
        if len(cells) < 3:
            continue

        ip_link = cells[0].find("a")
        port_link = cells[1].find("a")
        ip = ip_link.get_text(strip=True) if ip_link else cells[0].get_text(strip=True)
        port_text = (
            port_link.get_text(strip=True)
            if port_link
            else cells[1].get_text(strip=True)
        )

        try:
            port = int(port_text)
        except (TypeError, ValueError):
            continue
        if not valid_endpoint(ip, port):
            continue

        protocol = cells[2].get_text(" ", strip=True).lower()
        if protocol and "socks5" not in protocol:
            continue

        proxies.append(Proxy(ip=ip, port=port, protocol="socks5", source="ProxyDB"))
    return proxies


def fetch_proxydb(existing_keys: set[tuple[str, int]]) -> list[Proxy]:
    """Recorre el listado hasta reunir los 10 mejores proxies no repetidos."""
    session = make_session(
        "https://proxydb.net/",
        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    )
    selected: list[Proxy] = []
    seen = set(existing_keys)
    offset = 0
    pages = 0

    while len(selected) < PROXYDB_TOP and pages < PROXYDB_MAX_PAGES:
        print(f"[ProxyDB] descargando offset={offset} ...", file=sys.stderr)
        html = fetch_text(session, build_url(PROXYDB_URL, offset=offset))
        if html is None:
            break

        rows = parse_proxydb_rows(html)
        if not rows:
            break

        added = 0
        for proxy in rows:
            if proxy.key in seen:
                continue
            seen.add(proxy.key)
            selected.append(proxy)
            added += 1
            if len(selected) >= PROXYDB_TOP:
                break
        print(
            f"  {len(rows)} filas, {added} nuevas "
            f"(acumuladas {len(selected)}/{PROXYDB_TOP})",
            file=sys.stderr,
        )

        total = parse_proxydb_total(html)
        if total is not None and offset + PROXYDB_PAGE_SIZE >= total:
            break
        offset += PROXYDB_PAGE_SIZE
        pages += 1
        if len(selected) < PROXYDB_TOP:
            time.sleep(1.0 + random.uniform(0, 0.3))

    return selected


# --------------------------------------------------------------------------- #
# spys.one (HTML con puertos ofuscados)
# --------------------------------------------------------------------------- #
RE_VARS_BLOCK = re.compile(r'<script type="text/javascript">([a-z0-9=;^]+)</script>')
RE_PACKED = re.compile(
    r"eval\(function\(p,r,o,x,y,s\)\{.*?\}\('(.*?)',(\d+),(\d+),'(.*?)'\.split\(",
    re.S,
)
RE_ROW = re.compile(r"<tr class=spy1x[x]?[^>]*>(.*?)</tr>", re.S)
RE_CELL = re.compile(r"<td colspan=1>(.*?)</td>", re.S)
RE_IP = re.compile(r"class=spy14>(\d+\.\d+\.\d+\.\d+)<script")
RE_PORT_SCRIPT = re.compile(
    r"<script[^>]*>(document\.write\(.*?\))</script>", re.S
)
RE_XOR_TERM = re.compile(r"\(([A-Za-z0-9]+)\s*\^\s*([A-Za-z0-9]+)\)")
RE_TYPE = re.compile(r"\b(HTTP|HTTPS|SOCKS5|SOCKS4)\b")

BASE36 = "0123456789abcdefghijklmnopqrstuvwxyz"


def js_base36(value: int) -> str:
    """Equivalente a Number.prototype.toString(36) en JavaScript."""
    if value == 0:
        return "0"
    out = ""
    while value > 0:
        out = BASE36[value % 36] + out
        value //= 36
    return out


def js_y(value: int, radix: int) -> str:
    """Conversor base-N del packer de spys.one."""
    head = "" if value < radix else js_y(value // radix, radix)
    value = value % radix
    tail = chr(value + 29) if value > 35 else js_base36(value)
    return head + tail


def eval_packed_expr(expression: str, variables: dict[str, int]) -> int | None:
    """Evalúa `numero` o `A^B` con los valores ya conocidos."""
    if "^" in expression:
        left, right = expression.split("^", 1)
        left_value = eval_packed_expr(left.strip(), variables)
        right_value = eval_packed_expr(right.strip(), variables)
        if left_value is None or right_value is None:
            return None
        return left_value ^ right_value
    expression = expression.strip()
    if expression.isdigit():
        return int(expression)
    return variables.get(expression)


def parse_packed_vars(html: str) -> dict[str, int]:
    """Desempaqueta el script ofuscado de los listados por país."""
    match = RE_PACKED.search(html)
    if match is None:
        return {}

    payload, radix, offset, dictionary = match.groups()
    radix = int(radix)
    offset = int(offset)
    entries = dictionary.split("^")

    table: dict[str, str] = {}
    index = offset
    while index > 0:
        index -= 1
        key = js_y(index, radix)
        value = entries[index] if index < len(entries) else ""
        table[key] = value if value else key

    def replace(match_obj: re.Match) -> str:
        return table.get(match_obj.group(0), match_obj.group(0))

    code = re.sub(r"\b\w+\b", replace, payload)

    variables: dict[str, int] = {}
    for statement in code.split(";"):
        if "=" not in statement:
            continue
        name, expression = statement.split("=", 1)
        value = eval_packed_expr(expression.strip(), variables)
        if value is not None:
            variables[name.strip()] = value
    return variables


def eval_expr(expression: str, variables: dict[str, int]) -> int:
    """Evalúa una expresión del bloque de variables (números y XOR)."""
    expression = expression.strip()
    if "^" in expression:
        left, right = expression.split("^", 1)
        return eval_expr(left, variables) ^ eval_expr(right, variables)
    if expression.isdigit():
        return int(expression)
    return variables[expression]


def parse_spys_vars(html: str) -> dict[str, int]:
    """Lee las variables numéricas de la página (esquema simple y empaquetado)."""
    variables: dict[str, int] = {}
    for block in RE_VARS_BLOCK.findall(html):
        for statement in block.split(";"):
            if "=" not in statement:
                continue
            name, expression = statement.split("=", 1)
            try:
                variables[name.strip()] = eval_expr(expression.strip(), variables)
            except (KeyError, ValueError):
                continue
    for name, value in parse_packed_vars(html).items():
        variables.setdefault(name, value)
    return variables


def decode_port(script: str, variables: dict[str, int]) -> str:
    """Convierte el document.write ofuscado en el texto con el puerto."""
    digits: list[str] = []
    for left, right in RE_XOR_TERM.findall(script):
        try:
            value = variables[left] ^ variables[right]
        except KeyError:
            continue
        digits.append(str(value))
    return "".join(digits)


def parse_spys_rows(html: str) -> list[Proxy]:
    variables = parse_spys_vars(html)
    proxies: list[Proxy] = []

    for row_html in RE_ROW.findall(html):
        cells = RE_CELL.findall(row_html)
        if len(cells) < 2:
            continue

        ip_match = RE_IP.search(cells[0])
        script_match = RE_PORT_SCRIPT.search(cells[0])
        if ip_match is None or script_match is None:
            continue

        ip = ip_match.group(1)
        port_text = decode_port(script_match.group(1), variables)
        if not port_text.isdigit():
            continue

        port = int(port_text)
        if not valid_endpoint(ip, port):
            continue

        type_match = RE_TYPE.search(re.sub(r"<[^>]+>", " ", cells[1]))
        if type_match and type_match.group(1) != "SOCKS5":
            continue

        proxies.append(Proxy(ip=ip, port=port, protocol="socks5", source="Spys.one"))
    return proxies


def fetch_spys() -> list[Proxy]:
    session = make_session(
        "https://spys.one/",
        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    )
    print(f"[Spys.one] descargando {SPYS_URL} ...", file=sys.stderr)
    html = fetch_text(session, SPYS_URL, check_cloudflare=True)
    if html is None:
        return []

    proxies = parse_spys_rows(html)
    print(f"  {len(proxies)} proxies SOCKS5", file=sys.stderr)
    return proxies


# --------------------------------------------------------------------------- #
# Verificación
# --------------------------------------------------------------------------- #
def is_usable_response(response: requests.Response) -> bool:
    """Comprueba que la respuesta viene realmente del sitio de control."""
    if response.status_code >= 400:
        return False
    body = response.text.strip()
    if not body:
        return False
    try:
        response.json()
        return True
    except ValueError:
        pass
    head = body[:200].lower()
    return not any(marker in head for marker in ("<html", "<!doctype", "error page"))


def check_proxy(proxy: Proxy) -> bool:
    """Comprueba que el proxy responde como SOCKS5."""
    proxy_url = f"socks5h://{proxy.ip}:{proxy.port}"
    proxies = {"http": proxy_url, "https": proxy_url}
    for attempt in range(VERIFY_ATTEMPTS):
        try:
            response = requests.get(
                VERIFY_URL,
                proxies=proxies,
                timeout=VERIFY_TIMEOUT,
                verify=False,
            )
            if is_usable_response(response):
                return True
        except Exception:
            pass
        if attempt < VERIFY_ATTEMPTS - 1:
            time.sleep(0.4)
    return False


def verify_sections(sections: list[tuple[str, list[Proxy]]]) -> list[tuple[str, list[Proxy]]]:
    all_proxies = [proxy for _name, proxies in sections for proxy in proxies]
    if not all_proxies:
        return sections

    print(f"Verificando {len(all_proxies)} proxies ...", file=sys.stderr)
    alive: list[Proxy] = []
    with ThreadPoolExecutor(max_workers=VERIFY_WORKERS) as pool:
        futures = {pool.submit(check_proxy, proxy): proxy for proxy in all_proxies}
        for index, future in enumerate(as_completed(futures), start=1):
            proxy = futures[future]
            if future.result():
                alive.append(proxy)
            if index % 20 == 0 or index == len(all_proxies):
                print(
                    f"  {index}/{len(all_proxies)} probados -> {len(alive)} vivos",
                    file=sys.stderr,
                )

    alive_ids = {id(proxy) for proxy in alive}
    return [
        (name, [proxy for proxy in proxies if id(proxy) in alive_ids])
        for name, proxies in sections
    ]


# --------------------------------------------------------------------------- #
# Programa principal
# --------------------------------------------------------------------------- #
def deduplicate(
    proxies: Iterable[Proxy],
    seen: set[tuple[str, int]],
) -> list[Proxy]:
    unique: list[Proxy] = []
    for proxy in proxies:
        if proxy.key in seen:
            continue
        seen.add(proxy.key)
        unique.append(proxy)
    return unique


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Recolecta proxies SOCKS5 de Geonode, ProxyDB y Spys.one "
                    "en un único archivo agrupado por fuente.",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Comprobar que los proxies responden como SOCKS5",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=str(DEFAULT_OUTPUT),
        help="Archivo de salida",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    sections: list[tuple[str, list[Proxy]]] = []
    seen: set[tuple[str, int]] = set()

    collectors = [
        ("Geonode", fetch_geonode),
        ("ProxyDB", None),  # se ejecuta aparte: necesita los proxies ya vistos
        ("Spys.one", fetch_spys),
    ]

    for name, collector in collectors:
        try:
            if collector is None:
                found = fetch_proxydb(seen)
            else:
                found = collector()
        except Exception as exc:  # una fuente caída no debe abortar el resto
            print(f"  x {name}: {exc}", file=sys.stderr)
            found = []

        unique = deduplicate(found, seen)
        sections.append((name, unique))
        print(f"[{name}] {len(unique)} proxies", file=sys.stderr)

    if args.verify:
        sections = verify_sections(sections)
        if not any(proxies for _name, proxies in sections):
            print("Ningún proxy respondió.", file=sys.stderr)
            return 1

    lines: list[str] = []
    total = 0
    for name, proxies in sections:
        if not proxies:
            continue
        if lines:
            lines.append("")
        lines.append(f"# {name}")
        lines.extend(proxy.line for proxy in proxies)
        total += len(proxies)

    if total == 0:
        print("No se encontró ningún proxy.", file=sys.stderr)
        return 1

    output = Path(args.output)
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    except OSError as exc:
        print(f"No se pudo guardar {output}: {exc}", file=sys.stderr)
        return 1

    print(f"Guardados {total} proxies en {output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
