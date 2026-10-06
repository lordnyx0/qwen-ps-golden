"""collect-bash.py - coleta goldens bash-familia + MCP filesystem em runner descartavel.

NAO executa nada no host do dev: este script so roda dentro do workflow.
Entrada: calls.jsonl {uuid,idx,tool,arguments} (bash-familia + write_file,
create_directory, move_file, edit_file, + leitores MCP na parte 2).
Saida:   out/*.jsonl {uuid,idx,tool,arguments,ok,exit_code,stdout,stderr,refused}
Seguranca: jail /tmp (tudo fora dele e REFUSED) + blocklist + timeout 20s.
Fixture: /tmp/mcpfix montada no setup (idempotente).
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys

TIMEOUT = 20
MAX_CHARS = 32768
JAIL = "/tmp"
BLOCK = re.compile(
    r"(rm\s+-rf\s+/( |$)|mkfs|dd\s+if=|:?\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;?\s*:|"
    r"chmod|chown|sudo|shutdown|reboot|halt|poweroff|mkswap|swapon|"
    r"curl.*\|\s*(ba)?sh|wget.*\|\s*(ba)?sh|nc\s+-l|\bncat\b|meterpreter|mimikatz|"
    r"downloadstring|invoke-)",
    re.I,
)


def trunc(s):
    if len(s) > MAX_CHARS:
        return s[:MAX_CHARS] + "...[truncated]"
    return s


def _resolve(path):
    """Caminho absoluto canônico se dentro de /tmp, senao None (jail)."""
    p = str(path or "")
    full = os.path.normpath(p if os.path.isabs(p) else os.path.join("/tmp", p.lstrip("/")))
    real = os.path.realpath(full)
    if real == "/tmp" or real.startswith("/tmp" + os.sep):
        return real
    return None


def _jailed(path):
    """So aceita paths dentro de /tmp (resolve .. e links)."""
    return _resolve(path) is not None


PNG_1X1 = ("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGA"
           "hKmMIQAAAABJRU5ErkJggg==")

SVG_TPL = ('<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}">'
           "<title>{t}</title><rect width=\"{w}\" height=\"{h}\" fill=\"#{c}\"/></svg>\n")


def setup_fixture():
    """Monta /tmp/mcpfix (idempotente): move/src_NN + edit/doc_NN + read/ + media/."""
    import base64
    base = "/tmp/mcpfix"
    os.makedirs(os.path.join(base, "move"), exist_ok=True)
    os.makedirs(os.path.join(base, "edit"), exist_ok=True)
    os.makedirs(os.path.join(base, "read"), exist_ok=True)
    os.makedirs(os.path.join(base, "media"), exist_ok=True)
    os.makedirs("/tmp/mcpw", exist_ok=True)
    for i in range(1, 51):
        fp = os.path.join(base, "move", f"src_{i:03d}.txt")
        if not os.path.exists(fp):
            with open(fp, "w", encoding="utf-8") as f:
                f.write(f"move me {i}\n")
        fp = os.path.join(base, "edit", f"doc_{i:03d}.txt")
        if not os.path.exists(fp):
            with open(fp, "w", encoding="utf-8") as f:
                f.write(f"doc {i} version {i}\n")
    names = ["acorn", "birch", "clover", "dune", "elm", "fern", "gale", "heath", "iris", "jade",
             "kestrel", "lark", "maple", "north", "opal", "pine", "quill", "rowan", "spruce", "thyme",
             "ursa", "vetch", "wren", "yarrow", "zinc", "alto", "brisk", "cinder", "drift", "ember",
             "frost", "glade", "harbor", "inlet", "jetty", "knoll", "ledge", "marsh", "niche", "oasis",
             "plaza", "quay", "ridge", "shoal", "terrace", "upland", "vista", "wharf", "yonder", "zenith"]
    for i, nm in enumerate(names, 1):
        fp = os.path.join(base, "read", f"{nm}_{i:03d}.txt")
        if not os.path.exists(fp):
            with open(fp, "w", encoding="utf-8") as f:
                f.write(f"{nm} notes {i}\nline two of {nm}\nmarker_{nm} present here\n"
                        f"count {i * 3}\nend of {nm}\n")
    media = [("logo.png", None), ("photo.png", None), ("thumb.png", None),
             ("banner.svg", ("120", "40", "banner", "336699")),
             ("icon.svg", ("16", "16", "icon", "cc0000")),
             ("diagram.svg", ("400", "300", "diagram", "00aa55")),
             ("badge.svg", ("88", "20", "badge", "ffcc00")),
             ("chart.svg", ("200", "100", "chart", "5555ff")),
             ("map.svg", ("300", "200", "map", "77aa77")),
             ("hero.svg", ("640", "200", "hero", "222222"))]
    for fn, spec in media:
        fp = os.path.join(base, "media", fn)
        if os.path.exists(fp):
            continue
        if spec is None:
            with open(fp, "wb") as f:
                f.write(base64.b64decode(PNG_1X1))
        else:
            w, h, t, c = spec
            with open(fp, "w", encoding="utf-8") as f:
                f.write(SVG_TPL.format(w=w, h=h, t=t, c=c))


def run(argv, timeout=TIMEOUT):
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return r.returncode == 0, r.returncode, r.stdout or "", r.stderr or ""
    except subprocess.TimeoutExpired:
        return False, 124, "", f"TIMEOUT (> {timeout}s)"
    except Exception as e:  # noqa: BLE001 - erros reais viram golden de falha
        return False, 1, "", f"{type(e).__name__}: {e}", ""


def collect(call):
    tool = call.get("tool")
    args = call.get("arguments", {}) or {}
    refused = ""
    if tool in ("run_shell_command", "bash"):
        cmd = str(args.get("command", ""))
        if not cmd.strip():
            return False, -1, "", "", "empty command"
        if BLOCK.search(cmd):
            return False, 126, "", "", "REFUSED by collector blocklist"
        return (*run(["bash", "-c", cmd]), refused)
    if tool == "list_dir":
        return (*run(["ls", "-la", "--", str(args.get("path", "."))]), refused)
    if tool == "read_file":
        ok, code, out, err = run(["cat", "--", str(args.get("path", ""))])
        return ok, code, out[:MAX_CHARS], err, refused
    if tool == "compute_checksum":
        algo = str(args.get("algorithm", "sha256")).lower()
        exe = "md5sum" if algo == "md5" else "sha256sum"
        return (*run([exe, "--", str(args.get("path", ""))]), refused)
    if tool == "dns_lookup":
        return (*run(["getent", "hosts", str(args.get("domain", ""))], timeout=10), refused)
    if tool == "write_file":
        p, content = str(args.get("path", "")), str(args.get("content", ""))
        if not p or not _jailed(p):
            return False, 126, "", "", "REFUSED: fora de /tmp"
        try:
            full = _resolve(p) or ""
            os.makedirs(os.path.dirname(full), exist_ok=True)
            data = content.encode("utf-8")
            with open(full, "wb") as f:
                f.write(data)
            return True, 0, f"wrote {len(data)} bytes to {p}", "", refused
        except Exception as e:  # noqa: BLE001
            return False, 1, "", f"{type(e).__name__}: {e}", ""
    if tool == "create_directory":
        p = str(args.get("path", ""))
        if not p or not _jailed(p):
            return False, 126, "", "", "REFUSED: fora de /tmp"
        try:
            os.makedirs(_resolve(p) or "", exist_ok=True)
            return True, 0, f"created {p}", "", refused
        except Exception as e:  # noqa: BLE001
            return False, 1, "", f"{type(e).__name__}: {e}", ""
    if tool == "move_file":
        s, d = str(args.get("source", "")), str(args.get("destination", ""))
        if not s or not d or not _jailed(s) or not _jailed(d):
            return False, 126, "", "", "REFUSED: fora de /tmp"
        try:
            src = _resolve(s) or ""
            dst = _resolve(d) or ""
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.move(src, dst)
            return True, 0, f"moved {s} -> {d}", "", refused
        except Exception as e:  # noqa: BLE001
            return False, 1, "", f"{type(e).__name__}: {e}", ""
    if tool == "edit_file":
        p, old, new = (str(args.get("path", "")), str(args.get("old_string", "")),
                       str(args.get("new_string", "")))
        if not p or not old or not _jailed(p):
            return False, 126, "", "", "REFUSED: vazio ou fora de /tmp"
        try:
            full = _resolve(p) or ""
            with open(full, "r", encoding="utf-8") as f:
                text = f.read()
            n = text.count(old)
            if not n:
                return False, 1, "", f"old_string not found in {p}", ""
            text = text.replace(old, new, 1)
            with open(full, "w", encoding="utf-8") as f:
                f.write(text)
            return True, 0, f"replaced 1 occurrence in {p}", "", refused
        except Exception as e:  # noqa: BLE001
            return False, 1, "", f"{type(e).__name__}: {e}", ""
    if tool == "read_text_file":
        p = str(args.get("path", ""))
        if not p or not _jailed(p):
            return False, 126, "", "", "REFUSED: vazio ou fora de /tmp"
        head, tail = args.get("head"), args.get("tail")
        if head is not None and tail is not None:
            return False, 1, "", "cannot specify both head and tail", ""
        try:
            full = _resolve(p)
            with open(full, "r", encoding="utf-8") as f:
                lines = f.read().splitlines()
            if head is not None:
                lines = lines[:max(0, int(head))]
            elif tail is not None:
                lines = lines[max(0, len(lines) - int(tail)):]
            return True, 0, "\n".join(lines) + ("\n" if lines else ""), ""
        except Exception as e:  # noqa: BLE001
            return False, 1, "", f"{type(e).__name__}: {e}", ""
    if tool == "read_multiple_files":
        paths = args.get("paths", []) or []
        if not isinstance(paths, list) or not paths:
            return False, 126, "", "", "REFUSED: paths vazio"
        for p in paths:
            if not _jailed(p):
                return False, 126, "", "", "REFUSED: fora de /tmp"
        try:
            chunks = []
            for p in paths:
                with open(_resolve(p), "r", encoding="utf-8") as f:
                    chunks.append(f"--- {p} ---\n" + f.read())
            return True, 0, "".join(chunks), ""
        except Exception as e:  # noqa: BLE001
            return False, 1, "", f"{type(e).__name__}: {e}", ""
    if tool == "read_media_file":
        p = str(args.get("path", ""))
        if not p or not _jailed(p):
            return False, 126, "", "", "REFUSED: vazio ou fora de /tmp"
        try:
            full = _resolve(p)
            with open(full, "rb") as f:
                data = f.read()
            if data[:8] == b"\x89PNG\r\n\x1a\n":
                kind = "PNG"
            elif data.lstrip()[:4] == b"<svg" or b"<svg" in data[:200]:
                kind = "SVG"
            else:
                kind = "BIN"
            return True, 0, f"{kind} {len(data)} bytes: {p}", ""
        except Exception as e:  # noqa: BLE001
            return False, 1, "", f"{type(e).__name__}: {e}", ""
    if tool == "list_directory_with_sizes":
        p = str(args.get("path", ""))
        if not p or not _jailed(p):
            return False, 126, "", "", "REFUSED: vazio ou fora de /tmp"
        try:
            full = _resolve(p)
            out = []
            for name in sorted(os.listdir(full)):
                fp = os.path.join(full, name)
                out.append(f"{name}: {os.path.getsize(fp)} bytes")
            return True, 0, "\n".join(out) + ("\n" if out else ""), ""
        except Exception as e:  # noqa: BLE001
            return False, 1, "", f"{type(e).__name__}: {e}", ""
    if tool == "directory_tree":
        p = str(args.get("path", ""))
        if not p or not _jailed(p):
            return False, 126, "", "", "REFUSED: vazio ou fora de /tmp"
        try:
            full = _resolve(p)
            out = []
            for root, dirs, files in os.walk(full):
                dirs.sort()
                rel = os.path.relpath(root, full)
                depth = 0 if rel == "." else rel.count(os.sep) + 1
                out.append(("  " * depth) + (os.path.basename(full) if rel == "." else os.path.basename(root)))
                for fn in sorted(files):
                    out.append(("  " * (depth + 1)) + fn)
            return True, 0, "\n".join(out) + "\n", ""
        except Exception as e:  # noqa: BLE001
            return False, 1, "", f"{type(e).__name__}: {e}", ""
    if tool == "search_files":
        pat, scope = str(args.get("pattern", "")), str(args.get("path", "/tmp/mcpfix"))
        if not pat or not _jailed(scope):
            return False, 126, "", "", "REFUSED: vazio ou fora de /tmp"
        return (*run(["grep", "-rn", "--", pat, _resolve(scope)]), refused)
    if tool == "get_file_info":
        p = str(args.get("path", ""))
        if not p or not _jailed(p):
            return False, 126, "", "", "REFUSED: vazio ou fora de /tmp"
        try:
            full = _resolve(p)
            kind = "dir" if os.path.isdir(full) else "file"
            return True, 0, f"{p}: {kind}, {os.path.getsize(full)} bytes", ""
        except Exception as e:  # noqa: BLE001
            return False, 1, "", f"{type(e).__name__}: {e}", ""
    return False, -1, "", "", f"unsupported tool: {tool}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--calls", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "bash_calls.jsonl"))
    ap.add_argument("--out", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "out", "bash_results.jsonl"))
    ap.add_argument("--no-fixture", action="store_true")
    a = ap.parse_args()
    if not a.no_fixture:
        setup_fixture()
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    n_ok = n_err = n_ref = 0
    total = 0
    with open(a.calls, encoding="utf-8") as fin, open(a.out, "w", encoding="utf-8") as fout:
        for line in fin:
            if not line.strip():
                continue
            c = json.loads(line)
            total += 1
            ok, code, out, err, refused = collect(c)
            if refused:
                n_ref += 1
            elif ok:
                n_ok += 1
            else:
                n_err += 1
            fout.write(json.dumps({"uuid": c.get("uuid"), "idx": c.get("idx"), "tool": c.get("tool"),
                                   "arguments": c.get("arguments", {}), "ok": ok, "exit_code": code,
                                   "stdout": trunc(out), "stderr": trunc(err), "refused": refused},
                                  ensure_ascii=False) + "\n")
    print(f"OK={n_ok} ERR={n_err} REFUSED={n_ref} total={total} -> {a.out}")


if __name__ == "__main__":
    sys.exit(main())
