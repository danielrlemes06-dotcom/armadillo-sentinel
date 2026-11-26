import argparse

from .db import insert_events
from .parser import parse_file
from .detectors import run_detectors, list_alerts


def main():
    ap = argparse.ArgumentParser(prog="sentinel")
    sub = ap.add_subparsers(dest="command", required=True)

    imp = sub.add_parser("import", help="Importa logs para o banco")
    imp.add_argument("path", help="Caminho do arquivo de log")
    imp.add_argument("--year", type=int, default=None)

    sub.add_parser("detect", help="Executa os detectores de segurança")
    sub.add_parser("alerts", help="Lista os alertas encontrados")

    args = ap.parse_args()

    if args.command == "import":
        events = parse_file(args.path, year=args.year)
        total = insert_events(events)
        print(f"{total} eventos importados de {args.path}")

    elif args.command == "detect":
        results = run_detectors()
        print("\n=== RESULTADO DA ANÁLISE ===")
        for name, total in results.items():
            print(f"{name}: {total} alerta(s)")

        print(f"Total: {sum(results.values())} alerta(s)")

    elif args.command == "alerts":
        alerts = list_alerts()

        print("\n=== ALERTAS DO ARMADILLO SENTINEL ===")

        if not alerts:
            print("Nenhum alerta encontrado.")
            return

        for alert in alerts:
            alert_type, ip, severity, description, created_at = alert
            print(f"\nTipo: {alert_type}")
            print(f"IP: {ip}")
            print(f"Severidade: {severity.upper()}")
            print(f"Descrição: {description}")
            print(f"Data: {created_at}")


if __name__ == "__main__":
    main()
