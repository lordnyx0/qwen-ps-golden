"""collect-bash.py - coleta goldens bash-familia em runner descartavel (GitHub ubuntu-latest).

NAO executa nada no host do dev: este script so roda dentro do workflow.
Entrada: bash_calls.jsonl {uuid,idx,tool,arguments} (run_shell_command|list_dir|read_file|compute_checksum|dns_lookup)
Saida:   out/bash_results.jsonl {uuid,idx,tool,arguments,ok,exit_code,stdout,stderr,refused}
Seguranca: blocklist antes de executar + subprocess com timeout 20s + truncate 32KB.
"""
import argparse
import json
import os
import re
import subprocess
import sys

TIMEOUT = 20
MAX_CHARS = 32768
BLOCK = re.compile(
    r"(rm\s+-rf\s+/( |$)|mkfs|dd\s+if=|:?\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;?\s*:|"
    r"chmod|chown|sudo|shutdown|reboot|halt|poweroff|mkswap|swapon|"
    r"curl.*\|\s*(ba)?sh|wget.*\|\s*(ba)?sh|nc\s+-l|ncat|meterpreter|mimikatz|"
    r"downloadstring|invoke-)",
    re.I,
)


def trunc(s):
    if len(s) > MAX_CHARS:
        return s[:MAX_CHARS] + "...[truncated]"
    return s


def run(argv, timeout=TIMEOUT):
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return r.returncode == 0, r.returncode, r.stdout or "", r.stderr or ""
    except subprocess.TimeoutExpired:
        return False, 124, "", f"TIMEOUT (> {timeout}s)"
    except Exception as e:  # noqa: BLE001 - erros reais viram golden de falha
        return False, 1, "", f"{type(e).__name__}: {e}"


def collect(call):
    tool = call.get("tool")
    args = call.get("arguments", {}) or {}
    refused = ""
    if tool == "run_shell_command":
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
    return False, -1, "", "", f"unsupported tool: {tool}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--calls", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "bash_calls.jsonl"))
    ap.add_argument("--out", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "out", "bash_results.jsonl"))
    a = ap.parse_args()
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
