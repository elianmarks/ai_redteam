#!/usr/bin/env python3
"""
tools/test_connection.py

Validates the connection to a target agent before running the full framework.
Executes the complete flow: cookies → session init → greeting → test message.

Usage:
    python tools/test_connection.py --target-file my_target.yaml
    python tools/test_connection.py --target-file my_target.yaml --skip-browser
    python tools/test_connection.py --target-file my_target.yaml --proxy http://127.0.0.1:8080
    python tools/test_connection.py --target-file my_target.yaml --message "Hello, what can you help me with?"
"""
import argparse
import logging
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from services.cookie_manager import CookieManager
from services.target_adapter import TargetAdapter

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("test_connection")

DEFAULT_TARGET = "config/targets/template_target.yaml"
TARGETS_DIR    = "config/targets"


def resolve_target_path(target_file: str) -> str:
    """Resolve o path do YAML do alvo — aceita nome simples ou path completo."""
    if os.path.exists(target_file):
        return target_file
    candidate = os.path.join(TARGETS_DIR, target_file)
    if os.path.exists(candidate):
        return candidate
    if not target_file.endswith(".yaml"):
        candidate2 = os.path.join(TARGETS_DIR, target_file + ".yaml")
        if os.path.exists(candidate2):
            return candidate2
    return target_file  # deixar falhar com erro claro


def run_test(target_path: str, skip_browser: bool, test_message: str, proxy: str = None):
    import yaml

    if not os.path.exists(target_path):
        print(f"\n❌ Target file not found: {target_path}")
        print(f"   Available targets in {TARGETS_DIR}/:")
        for f in sorted(os.listdir(TARGETS_DIR)):
            if f.endswith(".yaml"):
                print(f"     - {f}")
        return False

    with open(target_path) as f:
        cfg = yaml.safe_load(f)

    target_name       = cfg.get("target", {}).get("name", "Unknown Target")
    token_name        = cfg.get("session_token", {}).get("name", "session_token")
    init_endpoint     = cfg.get("session_token", {}).get("init_endpoint", "")
    browser_url       = cfg.get("browser", {}).get("url",
                        cfg.get("target", {}).get("base_url", ""))

    print("\n" + "="*60)
    print(f"  Connection Test — {target_name}")
    print("="*60 + "\n")
    print(f"  Target file : {target_path}")
    print(f"  Base URL    : {cfg.get('target', {}).get('base_url', '?')}")
    print(f"  Chat endpoint: {cfg.get('target', {}).get('endpoints', {}).get('chat', '?')}")
    if init_endpoint:
        print(f"  Session init : {init_endpoint} → {token_name}")
    print()

    # Aplicar proxy se fornecido
    config_path = target_path
    if proxy:
        cfg["proxy"] = {"enabled": True, "http": proxy, "https": proxy, "verify_ssl": False}
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False)
        yaml.dump(cfg, tmp)
        tmp.flush()
        config_path = tmp.name
        print(f"🔀 Proxy: {proxy}\n")

    adapter = TargetAdapter(config_path)

    # Step 1 — Capturar cookies via browser
    if not skip_browser and browser_url:
        antibot_msg = cfg.get("browser", {}).get("antibot_instructions", "Resolve the challenge and press ENTER.")
        cm = CookieManager(target_url=browser_url, config_path=config_path)
        print("→ Step 1: Opening browser for cookie capture...")
        cookies = cm.refresh(reason=f"Connection test — {antibot_msg.splitlines()[0]}")
        if cookies:
            adapter.update_session_cookies(cookies)
            print(f"  ✅ {len(cookies)} cookies captured\n")
        else:
            print("  ⚠️  No cookies captured — trying with YAML cookies\n")
    else:
        if skip_browser:
            print("→ Step 1: Skipped (--skip-browser)\n")
        else:
            print("→ Step 1: No browser.url configured — skipping cookie capture\n")

    # Step 2 — Inicializar sessão (token)
    if init_endpoint:
        print(f"→ Step 2: Initializing session ({init_endpoint.split('/')[-1]} → {token_name})...")
        success = adapter.init_session()
        if success:
            print(f"  ✅ {token_name}: {adapter.session_token[:50]}...\n")
        else:
            print(f"  ❌ Failed to obtain {token_name}\n")
            return False
    else:
        print("→ Step 2: No session_token.init_endpoint configured — skipping\n")

    # Step 3 — Greeting (opcional)
    if cfg.get("target", {}).get("endpoints", {}).get("greeting"):
        print("→ Step 3: Fetching greeting...")
        greeting = adapter.get_greeting()
        if greeting:
            print(f"  ✅ Greeting: {greeting[:100]}...\n")
        else:
            print("  ⚠️  Greeting empty or failed (non-critical)\n")
    else:
        print("→ Step 3: No greeting endpoint configured — skipping\n")

    # Step 4 — Enviar mensagem de teste
    print(f"→ Step 4: Sending test message: \"{test_message}\"")
    response = adapter.send_message(test_message)

    if response["success"]:
        print(f"\n  ✅ Response received (HTTP {response['status_code']})")
        print(f"  Text: {response['extracted_text'][:300]}")
        sse_count = len(response.get("sse_events", []))
        if sse_count:
            print(f"  SSE events captured: {sse_count}")
        print("\n" + "="*60)
        print(f"  CONNECTION OK — ready to run the framework against {target_name}")
        print("="*60 + "\n")
        return True
    else:
        blocked = response.get("blocked", False)
        print(f"\n  ❌ Failed (HTTP {response['status_code']})")
        print(f"  Error: {response.get('error', 'unknown')}")
        if blocked:
            print("  ⚠️  BLOCKED — refresh cookies and try again")
        print("="*60 + "\n")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Test connection to a target AI agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python tools/test_connection.py --target-file my_target.yaml
  python tools/test_connection.py --target-file my_target.yaml --skip-browser
  python tools/test_connection.py --target-file my_target.yaml --proxy http://127.0.0.1:8080
  python tools/test_connection.py --target-file my_target.yaml --message "Hi, what can you help me with?"
        """
    )
    parser.add_argument(
        "--target-file", required=True, metavar="FILENAME",
        help="Target YAML filename in config/targets/ (e.g. my_target.yaml) or full path"
    )
    parser.add_argument(
        "--skip-browser", action="store_true",
        help="Skip browser opening — use cookies already set in YAML"
    )
    parser.add_argument(
        "--message", default="Hi! Can you help me? What can you assist me with?",
        help="Test message to send to the agent"
    )
    parser.add_argument(
        "--proxy", type=str, default=None,
        help="Proxy for requests, e.g. http://127.0.0.1:8080 (Burp Suite)"
    )
    args = parser.parse_args()

    target_path = resolve_target_path(args.target_file)
    run_test(target_path, args.skip_browser, args.message, args.proxy)


if __name__ == "__main__":
    main()
