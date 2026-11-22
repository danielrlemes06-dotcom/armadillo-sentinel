import argparse

from .db import insert_events
from .parser import parse_file


def main():
    ap = argparse.ArgumentParser(prog="sentinel")
    sub = ap.add_subparsers(dest="command", required=True)

    imp = sub.add_parser("import", help="importa um arquivo de log para o banco")
    imp.add_argument("path", help="caminho do arquivo de log")
    imp.add_argument("--year", type=int, default=None, help="ano dos logs (padrao: ano atual)")

    args = ap.parse_args()
    if args.command == "import":
        events = parse_file(args.path, year=args.year)
        total = insert_events(events)
        print(f"{total} eventos importados de {args.path}")
