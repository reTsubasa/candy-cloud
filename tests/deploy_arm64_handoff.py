#!/usr/bin/env python3
"""Opt-in real Docker/Caddy gate for the production rolling helper functions.

Uses only the existing caddy:2.9-alpine image. Does not build/pull application
images or touch any existing deployment, container, volume, or network.
"""
import concurrent.futures
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import time
import urllib.request


ROOT = Path(__file__).resolve().parents[1]


def run(args, **kwargs):
    result = subprocess.run(args, text=True, capture_output=True, **kwargs)
    if result.returncode:
        raise RuntimeError(f"{args}: {result.stdout}\n{result.stderr}")
    return result


def main():
    run(["docker", "image", "inspect", "caddy:2.9-alpine"])
    with tempfile.TemporaryDirectory(prefix="candy-cloud-handoff-") as temporary:
        directory = Path(temporary)
        project = f"candy-handoff-{os.getpid()}"
        revision = f"gate-{os.getpid()}"
        services = {"cloud-api": 8080, "cloud-identity": 8082, "cloud-auth": 8081,
                    "cloud-worker": 8090, "cloud-web": 8091}
        configurations = {}
        definitions = {}
        for service, port in services.items():
            configuration = directory / f"{service}.Caddyfile"
            configuration.write_text(f":{port} {{\n respond \"old-{service}\"\n}}\n")
            configurations[service] = configuration
            definitions[service] = {
                "image": "caddy:2.9-alpine",
                "volumes": [f"{configuration}:/etc/caddy/Caddyfile:ro"],
                "healthcheck": {"test": ["CMD", "wget", "-qO-", f"http://127.0.0.1:{port}/"],
                                "interval": "1s", "timeout": "1s", "retries": 10},
            }
        proxy = directory / "Caddyfile.previous"
        proxy.write_text(":8088 {\n"
                         " handle /api {\n  reverse_proxy cloud-api:8080\n }\n"
                         " handle /identity {\n  reverse_proxy cloud-identity:8082\n }\n"
                         " handle /auth {\n  reverse_proxy cloud-auth:8081\n }\n}\n")
        definitions["reverse-proxy"] = {
            "image": "caddy:2.9-alpine",
            "volumes": [f"{proxy}:/etc/caddy/Caddyfile:ro"],
            "ports": ["127.0.0.1::8088"],
        }
        composition = directory / "compose.json"
        composition.write_text(json.dumps({"services": definitions}))
        compose = ["docker", "compose", "-p", project, "-f", str(composition)]
        stop = threading.Event()
        samples = []
        errors = []
        lock = threading.Lock()
        try:
            run(compose + ["up", "-d", "--wait", "--wait-timeout", "60"], timeout=90)
            proxy_id = run(compose + ["ps", "-q", "reverse-proxy"]).stdout.strip()
            address = run(compose + ["port", "reverse-proxy", "8088"]).stdout.strip()
            base = f"http://{address}"

            def sample(route):
                while not stop.is_set():
                    try:
                        with urllib.request.urlopen(f"{base}/{route}", timeout=3) as response:
                            value = response.read().decode()
                            if response.status != 200:
                                raise AssertionError(response.status)
                        with lock:
                            samples.append((route, value))
                    except Exception as error:
                        with lock:
                            errors.append((route, str(error)))
                    stop.wait(0.025)

            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
                futures = [executor.submit(sample, route) for route in ("api", "identity", "auth")]
                # Existing Caddy processes retain their loaded old configuration.
                for service, port in services.items():
                    configurations[service].write_text(f":{port} {{\n respond \"new-{service}\"\n}}\n")
                source = (ROOT / "scripts/deploy-arm64-release.sh").read_text()
                functions = source[source.index("service_healthy() {"):source.index("restore_database() {")]
                harness = directory / "handoff.sh"
                harness.write_text("#!/bin/sh\nset -eu\n"
                                   'compose() { docker compose -p "$project" -f "$fixture" "$@"; }\n'
                                   + functions + "\nrolling_services\n")
                environment = dict(os.environ, project=project, fixture=str(composition),
                                   revision=revision, reverse_proxy_container=proxy_id,
                                   proxy_backup=str(proxy), transaction_dir=str(directory),
                                   drain_seconds="1", candidate_names="", proxy_switched="0",
                                   canonical_mutated="0")
                time.sleep(0.2)
                run(["sh", str(harness)], env=environment, timeout=120)
                time.sleep(0.2)
                stop.set()
                for future in futures:
                    future.result()
            assert not errors, errors[:10]
            for route in ("api", "identity", "auth"):
                observed = [value for name, value in samples if name == route]
                assert f"old-cloud-{route}" in observed, (route, observed[:5])
                assert f"new-cloud-{route}" in observed, (route, observed[-5:])
                assert set(observed) <= {f"old-cloud-{route}", f"new-cloud-{route}"}, route
            assert run(compose + ["ps", "-q", "reverse-proxy"]).stdout.strip() == proxy_id
            remaining = run(["docker", "ps", "-aq", "--filter", f"name=candy-next-{revision}-"]).stdout.strip()
            assert not remaining, remaining
            print(f"deploy_arm64_handoff: passed; {len(samples)} HTTP requests, zero failures, proxy unchanged")
        finally:
            stop.set()
            for service in ("cloud-api", "cloud-identity", "cloud-auth"):
                subprocess.run(["docker", "rm", "-f", f"candy-next-{revision}-{service}"],
                               capture_output=True)
            run(compose + ["down", "--remove-orphans"], timeout=60)


if __name__ == "__main__":
    main()
