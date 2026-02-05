"""Outclaw CLI – security toolkit entry point.

Subcommands:
    outclaw proxy   Start the LiteLLM proxy with security guards (default)
    outclaw init    Interactive secure config setup
    outclaw audit   Scan local system for security issues
    outclaw warmup  Pre-download ML models
"""

import argparse
import os
import sys


def _cmd_proxy(args: argparse.Namespace) -> None:
    from app.main import run_proxy

    run_proxy(host=args.host, port=args.port, token=args.token)


def _cmd_init(args: argparse.Namespace) -> None:
    from app.init_config import run_init

    run_init()


def _cmd_audit(args: argparse.Namespace) -> None:
    from app.audit import run_audit

    sys.exit(run_audit(fmt=args.format))


def _cmd_warmup(args: argparse.Namespace) -> None:
    """Pre-download ML models so first request isn't slow."""
    print("Warming up ML models...")

    # LlamaFirewall / PromptGuard 2
    try:
        from llamafirewall import LlamaFirewall, ScannerType
        print("  Downloading LlamaFirewall (PromptGuard 2)...")
        LlamaFirewall(scanners={ScannerType.PROMPT_GUARD: {}})
        print("  LlamaFirewall ready.")
    except ImportError:
        print("  LlamaFirewall not installed, skipping.")
    except Exception as e:
        print(f"  LlamaFirewall warmup failed: {e}")

    # Presidio (downloads spaCy model on first use)
    try:
        from presidio_analyzer import AnalyzerEngine
        print("  Initializing Presidio analyzer (may download spaCy model)...")
        AnalyzerEngine()
        print("  Presidio ready.")
    except ImportError:
        print("  Presidio not installed, skipping.")
    except Exception as e:
        print(f"  Presidio warmup failed: {e}")

    # llm-guard (optional heavy)
    try:
        from llm_guard.input_scanners import PromptInjection
        print("  Downloading llm-guard models...")
        PromptInjection()
        print("  llm-guard ready.")
    except ImportError:
        print("  llm-guard not installed (install with: pip install outclaw[heavy]), skipping.")
    except Exception as e:
        print(f"  llm-guard warmup failed: {e}")

    print("Warmup complete.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="outclaw",
        description="Outclaw – The Safety Shell for your AI Agent 🦞",
    )
    subs = parser.add_subparsers(dest="command")

    # --- proxy ---
    proxy_p = subs.add_parser("proxy", help="Start the security proxy")
    proxy_p.add_argument(
        "--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)"
    )
    proxy_p.add_argument(
        "--port",
        type=int,
        default=int(os.getenv("PORT", 8080)),
        help="Listen port (default: $PORT or 8080)",
    )
    proxy_p.add_argument(
        "--token", default=None, help="Bearer token to protect the proxy"
    )

    # --- init ---
    subs.add_parser("init", help="Interactive secure config setup")

    # --- audit ---
    audit_p = subs.add_parser("audit", help="Scan local system for security issues")
    audit_p.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )

    # --- warmup ---
    subs.add_parser("warmup", help="Pre-download ML models for faster first request")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command is None:
        # Default to proxy (backwards compat)
        args.command = "proxy"
        args.host = "127.0.0.1"
        args.port = int(os.getenv("PORT", 8080))
        args.token = None

    handlers = {
        "proxy": _cmd_proxy,
        "init": _cmd_init,
        "audit": _cmd_audit,
        "warmup": _cmd_warmup,
    }
    handlers[args.command](args)


if __name__ == "__main__":
    main()
