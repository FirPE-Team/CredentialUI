"""LCR transport for repeatable single-EXE WinPE acceptance evidence.

Examples:
  python scripts/test_winpe_single_exe.py exec baseline "ver & echo %TEMP%"
  python scripts/test_winpe_single_exe.py upload dist/x64/CredentialUI.exe X:\\CredentialUI_SingleExe\\CredentialUI.exe
  python scripts/test_winpe_single_exe.py spawn manager X:\\CredentialUI_SingleExe\\CredentialUI.exe
  python scripts/test_winpe_single_exe.py windows windows

Spawned commands follow LCR's task timeout. Explicitly stop the manager after
acceptance tests; use the PE's startup mechanism for ongoing operation.
"""
import json
import hashlib
import pathlib
import sys
import urllib.request
import urllib.error

BASE = "http://192.168.75.128:9527"
ROOT = pathlib.Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / "evidence" / "single-exe-2026-11-06"


def request(endpoint, payload=None, data=None, headers=None, timeout=45):
    if payload is not None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers = {"Content-Type": "application/json"}
    req = urllib.request.Request(BASE + "/" + endpoint, data=data or b"",
                                 headers=headers or {}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return response.read()
    except urllib.error.HTTPError as error:
        raise RuntimeError(error.read().decode("utf-8", errors="replace")) from error


def main():
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    action, label, *args = sys.argv[1:]
    if action == "upload":
        path = pathlib.Path(label)
        raw = request("upload", data=path.read_bytes(), headers={
            "Content-Type": "application/octet-stream", "X-File-Path": args[0]})
        label = "upload-" + path.stem
    elif action == "exec":
        raw = request("exec", {"command": " ".join(args), "interpreter": "cmd",
                                "timeout": 30000, "output_encoding": "utf8"})
    elif action == "spawn":
        raw = request("spawn", {"program": args[0], "args": args[1:]})
    elif action == "run":
        raw = request("exec", {"program": args[0], "args": args[1:], "timeout": 30000})
    elif action == "key":
        raw = request("control", {"actions": [
            {"type": "focus_window", "hwnd": args[0]},
            {"type": "keyboard", "key": args[1]}]})
    elif action == "navigate":
        raw = request("control", {"delay": 100, "actions": [
            {"type": "focus_window", "hwnd": args[0]},
            {"type": "keyboard", "key": "0x11", "state": "down"},
            {"type": "keyboard", "key": "L"},
            {"type": "keyboard", "key": "0x11", "state": "up"},
            {"type": "text", "text": args[1]},
            {"type": "keyboard", "key": "0x0D"}]})
    elif action == "result":
        raw = request("spawn/result", {"session_id": args[0],
                                        "stdout_offset": 0, "stderr_offset": 0})
    elif action == "screenshot":
        raw = request("screenshot")
        path = EVIDENCE / (label + ".png")
        path.write_bytes(raw)
        print(path)
        return
    elif action == "control":
        raw = request("control", json.loads(args[0]))
    elif action == "download":
        raw = request("download", {"path": args[0]})
        path = EVIDENCE / label
        path.write_bytes(raw)
        print(path)
        return
    elif action == "hash":
        raw = request("download", {"path": args[0]})
        raw = json.dumps({"path": args[0], "bytes": len(raw),
                          "sha256": hashlib.sha256(raw).hexdigest()}).encode("utf-8")
    else:
        raw = request(action)
    result = json.loads(raw)
    (EVIDENCE / (label + ".json")).write_text(
        json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    if action == "windows":
        result = [w for w in result.get("windows", []) if w.get("visible")]
    print(json.dumps(result, ensure_ascii=True, indent=2))


if __name__ == "__main__":
    main()
