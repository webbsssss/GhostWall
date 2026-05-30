"""
CLI for GhostWall.

Usage:
    python -m ghostwall.cli scan "some prompt here"
    python -m ghostwall.cli server
"""

import argparse
import sys
from ghostwall.core.pipeline import DetectionPipeline


def cmd_scan(args):
    pipeline = DetectionPipeline(config_path=args.config)
    result = pipeline.scan(args.text, session_id=args.session)

    print(f"Malicious: {result.is_malicious}")
    print(f"Risk:      {result.risk_level.value}")
    print(f"Label:     {result.final_label.value}")
    print(f"Confidence: {result.confidence:.3f}")
    print(f"Latency:   {result.latency_ms:.1f}ms")
    print("Layers:")
    for layer in result.layers:
        status = "TRIGGERED" if layer.triggered else "ok"
        print(f"  [{status}] {layer.layer}: score={layer.score:.3f} label={layer.label.value}")


def cmd_server(args):
    import uvicorn
    from ghostwall.api.server import app
    uvicorn.run(app, host=args.host, port=args.port)


def main():
    parser = argparse.ArgumentParser(prog="ghostwall")
    sub = parser.add_subparsers(dest="command")

    scan_parser = sub.add_parser("scan", help="scan a single prompt")
    scan_parser.add_argument("text", help="prompt text to scan")
    scan_parser.add_argument("--config", default=None, help="config yaml path")
    scan_parser.add_argument("--session", default=None, help="session id")

    srv_parser = sub.add_parser("server", help="run API server")
    srv_parser.add_argument("--host", default="0.0.0.0")
    srv_parser.add_argument("--port", type=int, default=8000)

    args = parser.parse_args()
    if args.command == "scan":
        cmd_scan(args)
    elif args.command == "server":
        cmd_server(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
