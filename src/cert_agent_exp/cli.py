"""CLI entrypoint."""

import argparse


def main() -> None:
    ap = argparse.ArgumentParser(prog="cert-agent-exp")
    ap.add_argument("--version", action="store_true", help="Show version")
    args = ap.parse_args()
    if args.version:
        from cert_agent_exp import __version__
        print(__version__)
        return
    ap.print_help()


if __name__ == "__main__":
    main()
