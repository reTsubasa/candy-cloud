#!/usr/bin/env python3
"""Execute the deployment transaction with only its host/network boundaries faked.

Real shell control flow, files, immutable manifest checks and SHA-256 verification
run unchanged. Docker readiness/reload behavior is covered by the Docker gate;
these cases inject failures deterministically into the entire rollback path.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
REVISION = "0123456789ab"


def boundary():
    fixture = Path(os.environ["CANDY_TRANSACTION_FIXTURE"])
    state_path = fixture / "state.json"
    state = json.loads(state_path.read_text()) if state_path.exists() else {}
    name = os.environ["CANDY_TRANSACTION_BOUNDARY_TOOL"]
    args = sys.argv[1:]
    event = {"tool": name, "args": args}
    code = 0
    signal_parent = False
    output = ""
    if name == "uname":
        output = "Linux" if args == ["-s"] else "aarch64"
    elif name == "id":
        output = "0"
    elif name == "curl":
        output_path = Path(args[args.index("--output") + 1])
        source = fixture / args[-1].rsplit("/", 1)[-1]
        shutil.copyfile(source, output_path)
    elif name == "docker":
        if args[:2] == ["compose", "version"]:
            output = "Docker Compose version v2.0.0"
        elif args[0] == "compose":
            tail = args[1:]
            compose_files = []
            while tail and tail[0] in ["--env-file", "-f"]:
                if tail[0] == "-f":
                    compose_files.append(tail[1])
                tail = tail[2:]
            command = tail[0]
            event["compose"] = tail
            if command == "ps":
                output = tail[-1]
            elif command == "exec":
                script = tail[-1]
                if "mysqldump" in script:
                    output = "-- Current Database: `candy_cloud`\nCREATE DATABASE candy_cloud;"
                    event["event"] = "db_backup"
                    state["backup_count"] = state.get("backup_count", 0) + 1
                    signal_parent = os.environ["CANDY_TRANSACTION_CASE"] == "maintenance_signal" and state["backup_count"] == 2
                elif "DROP DATABASE" in script:
                    event["event"] = "db_drop"
                elif "GRANT DELETE" in script:
                    event["event"] = "db_grant"
                else:
                    event["event"] = "db_restore"
                    sys.stdin.buffer.read()
            elif command == "run":
                if "--check-schema" in tail:
                    event["event"] = "schema_probe"
                    event["overrides"] = [Path(p).read_text() for p in compose_files]
                    code = {"schema_error": 2, "maintenance_failure": 3, "maintenance_signal": 3}.get(os.environ["CANDY_TRANSACTION_CASE"], 0)
                elif "--name" in tail:
                    candidate = tail[tail.index("--name") + 1]
                    event["event"] = "candidate_started"
                    event["candidate"] = candidate
                    output = candidate
                    if os.environ["CANDY_TRANSACTION_CASE"] == "candidate_creation_failure" and candidate.endswith("-cloud-identity"):
                        code = 1
                    else:
                        state.setdefault("candidates", []).append(candidate)
                else:
                    event["event"] = "migrate"
                    if os.environ["CANDY_TRANSACTION_CASE"] == "maintenance_failure":
                        code = 1
            elif command == "up":
                event["event"] = "canonical_up"
                state["up_calls"] = state.get("up_calls", 0) + 1
                if os.environ["CANDY_TRANSACTION_CASE"] == "rollback_failure" or (os.environ["CANDY_TRANSACTION_CASE"] == "canonical_failure" and state["up_calls"] == 1):
                    code = 1
            elif command in ["stop", "start"]:
                event["event"] = command
        elif args[:2] == ["image", "inspect"]:
            output = "arm64"
        elif args[0] == "inspect":
            container = args[1]
            template = args[-1]
            if ".Mounts" in template:
                output = "web-volume"
            elif ".State.Health" in template:
                output = "healthy"
                if os.environ["CANDY_TRANSACTION_CASE"] == "candidate_failure" and container.endswith("-cloud-identity") and container.startswith("candy-next-"):
                    output = "exited"
                event["event"] = "healthy" if output == "healthy" else "unhealthy"
                event["container"] = container
            else:
                output = "running"
        elif args[0] == "cp":
            source, destination = args[1:]
            if ":/etc/caddy/Caddyfile" in source:
                shutil.copyfile(fixture / "Caddyfile", destination)
            elif ":/srv/." in source:
                target = Path(destination)
                target.mkdir(exist_ok=True)
                (target / "assets").mkdir(exist_ok=True)
                (target / "assets/app.js").write_text("new app")
                (target / "index.html").write_text("new index")
            else:
                state["proxy_config"] = Path(source).read_text()
        elif args[0] == "exec" and "reload" in args:
            candidate = "candy-next-" in state.get("proxy_config", "")
            event["event"] = "switch_candidates" if candidate else "switch_canonical"
        elif args[0] == "run":
            if "web-volume.tar.gz -C /srv" in args[-1]:
                volume = next(item for item in args if item.endswith(":/backup"))
                (Path(volume[:-len(":/backup")]) / "web-volume.tar.gz").write_bytes(b"web-volume-backup")
                event["event"] = "web_backup"
            elif "tar -xzf /backup/web-volume.tar.gz" in args[-1]:
                event["event"] = "web_restore"
            else:
                event["event"] = "web_activate"
        elif args[0] == "create":
            output = "web-source"
        elif args[0] == "ps":
            candidate = args[-1].removeprefix("name=^/").removesuffix("$")
            if candidate in state.get("candidates", []):
                output = candidate
        elif args[0] == "rm":
            event["event"] = "remove"
            candidate = args[-1]
            if candidate.startswith("candy-next-"):
                candidates = state.setdefault("candidates", [])
                if os.environ["CANDY_TRANSACTION_CASE"] == "candidate_cleanup_failure" and not state.get("cleanup_failed_once"):
                    state["cleanup_failed_once"] = True
                    code = 1
                elif candidate not in candidates:
                    code = 1
                else:
                    candidates.remove(candidate)
    with (fixture / "events.jsonl").open("a") as stream:
        stream.write(json.dumps(event) + "\n")
    state_path.write_text(json.dumps(state))
    if output:
        print(output, flush=True)
    if signal_parent:
        os.kill(os.getppid(), signal.SIGTERM)
    raise SystemExit(code)


def positions(events, event):
    return [index for index, item in enumerate(events) if item.get("event") == event]


def run_case(case):
    with tempfile.TemporaryDirectory(prefix="candy-deploy-transaction-") as temporary:
        fixture = Path(temporary)
        binaries = fixture / "bin"
        deployment = fixture / "deployment"
        binaries.mkdir()
        deployment.mkdir()
        (deployment / "secrets").mkdir()
        for secret in ["cloud-api-auth-private.pem", "cloud-signing.key", "device-ca.key", "cloud-api-auth-public.pem", "device-ca.pem"]:
            (deployment / "secrets" / secret).write_text("fixture secret")
        (deployment / "deploy.env").write_text("MYSQL_DATABASE=candy_cloud\n")
        (deployment / "compose.arm64.yml").write_text("services: {}\n")
        previous = "services:\n  cloud-api:\n    image: previous-immutable-release\n"
        (deployment / "compose.arm64.release.yml").write_text(previous)
        (fixture / "Caddyfile").write_text("reverse_proxy cloud-api:8080\nreverse_proxy cloud-identity:8082\nreverse_proxy cloud-auth:8081\n")
        archive = f"candy-cloud-arm64-{REVISION}.tar.gz"
        (fixture / archive).write_bytes(b"immutable signed release fixture")
        digest = hashlib.sha256((fixture / archive).read_bytes()).hexdigest()
        (fixture / f"{archive}.sha256").write_text(f"{digest}  {archive}\n")
        (fixture / f"candy-cloud-arm64-{REVISION}.json").write_text(json.dumps({
            "schema_version": 1, "architecture": "arm64",
            "source": {"repository": "reTsubasa/candy-cloud", "commit": REVISION + "a" * 28},
            "images": ["migrate", "cloud-api", "cloud-identity", "cloud-auth", "cloud-worker", "cloud-web"],
            "core": {"version": "0.3.56", "bundle_sha256": "a" * 64, "module_sha256": "b" * 64},
        }))
        for name in ["curl", "docker", "uname", "id", "chown", "flock", "sleep"]:
            target = binaries / name
            target.write_text(f"#!{sys.executable}\nimport os\nos.environ['CANDY_TRANSACTION_BOUNDARY_TOOL'] = {name!r}\nimport runpy\nrunpy.run_path({str(Path(__file__).resolve())!r}, run_name='__main__')\n")
            target.chmod(0o755)
        environment = os.environ | {
            "PATH": str(binaries) + os.pathsep + os.environ["PATH"],
            "CANDY_TRANSACTION_FIXTURE": str(fixture), "CANDY_TRANSACTION_CASE": case,
            "CANDY_CLOUD_DRAIN_SECONDS": "1",
        }
        result = subprocess.run(["sh", str(ROOT / "scripts/deploy-arm64-release.sh"), "--tag", f"cloud-arm64-{REVISION}", "--deployment-dir", str(deployment)], env=environment, capture_output=True, text=True, timeout=120)
        events = [json.loads(line) for line in (fixture / "events.jsonl").read_text().splitlines()]
        diagnostic = f"case={case}\nstdout={result.stdout}\nstderr={result.stderr}\nevents={events}"
        assert (result.returncode == 0) == (case == "success"), diagnostic
        probes = positions(events, "schema_probe")
        assert len(probes) == 1, diagnostic
        assert f"candy-cloud-migrate:arm64-{REVISION}" in events[probes[0]]["overrides"][-1], diagnostic
        assert not any(item.get("compose", [None])[0] in ["stop", "down"] and "mysql" in item.get("compose", []) for item in events), diagnostic
        if case in ["success", "canonical_failure"]:
            switches = positions(events, "switch_candidates")
            assert len(switches) == 1, diagnostic
            readiness = [index for index, item in enumerate(events) if item.get("event") == "healthy" and item.get("container", "").startswith("candy-next-")]
            assert len(readiness) == 3 and max(readiness) < switches[0], diagnostic
            assert switches[0] < positions(events, "canonical_up")[0], diagnostic
            assert positions(events, "switch_canonical")[-1] > positions(events, "canonical_up")[-1], diagnostic
        if case in ["success", "candidate_failure", "canonical_failure", "candidate_creation_failure", "candidate_cleanup_failure"]:
            assert not positions(events, "stop"), diagnostic
            assert not positions(events, "migrate"), diagnostic
            assert not positions(events, "db_drop"), diagnostic
        if case in ["candidate_failure", "candidate_creation_failure"]:
            assert not positions(events, "switch_candidates"), diagnostic
            assert not positions(events, "canonical_up"), diagnostic
        if case in ["candidate_creation_failure", "candidate_cleanup_failure"]:
            final_state = json.loads((fixture / "state.json").read_text())
            assert not final_state.get("candidates"), diagnostic
        if case == "candidate_cleanup_failure":
            removals = [item["args"][-1] for item in events if item.get("event") == "remove" and item["args"][-1].startswith("candy-next-")]
            # The first removal fails, but both later candidates are still tried
            # before the remaining failure is retried during rollback.
            assert removals[:3] == [f"candy-next-{REVISION}-{service}" for service in ["cloud-api", "cloud-identity", "cloud-auth"]], diagnostic
        if case == "maintenance_failure":
            assert positions(events, "stop")[0] < positions(events, "db_backup")[-1] < positions(events, "migrate")[0], diagnostic
            assert positions(events, "db_drop") and positions(events, "db_restore"), diagnostic
        if case == "maintenance_signal":
            assert positions(events, "stop") and positions(events, "canonical_up"), diagnostic
            assert not positions(events, "migrate") and not positions(events, "db_drop"), diagnostic
            assert "previous Cloud release restored" in result.stderr, diagnostic
        if case != "schema_error":
            checksums = list((deployment / "backups").glob("*/rollback.sha256"))
            assert len(checksums) == 1 and "Caddyfile.previous" in checksums[0].read_text(), diagnostic
        if case == "rollback_failure":
            marker = deployment / ".deployment-recovery-required"
            assert marker.exists(), diagnostic
            retry = subprocess.run(["sh", str(ROOT / "scripts/deploy-arm64-release.sh"), "--tag", f"cloud-arm64-{REVISION}", "--deployment-dir", str(deployment)], env=environment, capture_output=True, text=True, timeout=30)
            assert retry.returncode != 0 and "manual recovery" in retry.stderr, diagnostic
            updated = [json.loads(line) for line in (fixture / "events.jsonl").read_text().splitlines()]
            assert positions(updated, "canonical_up") == positions(events, "canonical_up"), diagnostic
        else:
            assert not (deployment / ".deployment-recovery-required").exists(), diagnostic
        if case == "schema_error":
            assert not positions(events, "canonical_up") and not positions(events, "migrate"), diagnostic
        if case != "success":
            assert (deployment / "compose.arm64.release.yml").read_text() == previous, diagnostic
        print(f"deploy_arm64_transaction: {case}: ok", flush=True)


if __name__ == "__main__":
    if os.environ.get("CANDY_TRANSACTION_BOUNDARY_TOOL"):
        boundary()
    else:
        for case in ["success", "candidate_failure", "candidate_creation_failure", "candidate_cleanup_failure", "canonical_failure", "maintenance_failure", "maintenance_signal", "rollback_failure", "schema_error"]:
            run_case(case)
