from __future__ import annotations

import argparse
import logging
import os
import platform
import shutil
import time
from pathlib import Path

from . import banner, diff, exporters
from .config import DEFAULT_PROFILE, PROFILES, apply_cli_overrides, load_profile, merge_config_file
from .intel_db import IntelDB
from .pipeline import Pipeline
from .sources import SourceContext, instantiate_all

VERSION = "3.2.2"

# internal_key_name -> (cli flag, .env / shell env var name)
KEY_FLAGS = {
    "github": ("--github-token", "GITHUB_TOKEN"),
    "censys_id": ("--censys-id", "CENSYS_API_ID"),
    "censys_secret": ("--censys-secret", "CENSYS_API_SECRET"),
    "virustotal": ("--virustotal-key", "VIRUSTOTAL_API_KEY"),
    "urlscan": ("--urlscan-key", "URLSCAN_API_KEY"),
    "certspotter": ("--certspotter-key", "CERTSPOTTER_API_KEY"),
    "fullhunt": ("--fullhunt-key", "FULLHUNT_API_KEY"),
    "chaos": ("--chaos-key", "CHAOS_API_KEY"),
}


def _flag_to_dest(flag: str) -> str:
    return flag.lstrip("-").replace("-", "_")


def _load_dotenv(path: str = ".env") -> dict[str, str]:
    values: dict[str, str] = {}
    p = Path(path)
    if not p.exists():
        return values
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        values[k.strip()] = v.strip().strip('"').strip("'")
    return values


def _resolve_api_keys(args: argparse.Namespace) -> dict[str, str | None]:
    """Priority: --flag-on-cli > real shell environment variable > .env file."""
    dotenv = _load_dotenv()
    keys: dict[str, str | None] = {}
    for internal_name, (flag, env_name) in KEY_FLAGS.items():
        cli_val = getattr(args, _flag_to_dest(flag), None)
        shell_val = os.environ.get(env_name)
        dotenv_val = dotenv.get(env_name) or None
        keys[internal_name] = cli_val or shell_val or dotenv_val
    return keys


def _load_domain_list(path: str) -> list[str]:
    """Reads one domain per line from a text file (e.g. example.txt).
    Blank lines and lines starting with '#' are skipped. Order is
    preserved; duplicates are dropped."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Domain list file not found: {path}")
    seen: set[str] = set()
    domains: list[str] = []
    for line in p.read_text(encoding="utf-8").splitlines():
        d = line.strip()
        if not d or d.startswith("#"):
            continue
        d = d.lower()
        if d not in seen:
            seen.add(d)
            domains.append(d)
    return domains


def _resolve_domains(args: argparse.Namespace) -> list[str]:
    domains: list[str] = []
    seen: set[str] = set()
    if args.domain:
        d = args.domain.strip().lower()
        domains.append(d)
        seen.add(d)
    if args.domain_list:
        for d in _load_domain_list(args.domain_list):
            if d not in seen:
                seen.add(d)
                domains.append(d)
    return domains


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sazzad007",
        description="Passive + active subdomain recon: many free OSINT sources, deep "
                     "recursive enumeration, smart wildcard filtering, cloud/ASN "
                     "discovery, a configurable confidence engine, and multi-format "
                     "reporting (with a queryable SQLite intelligence DB + diff mode).",
    )
    p.add_argument("-d", "--domain", help="Target domain, e.g. example.com")
    p.add_argument("-dL", "--domain-list", metavar="FILE",
                    help="Path to a text file with one domain per line (e.g. example.txt) "
                         "-- runs the full pipeline against every domain in the file. Can "
                         "be combined with -d (both are scanned). Each domain gets its own "
                         "output subfolder: <output-dir>/<domain>/...")
    p.add_argument("--profile", choices=list(PROFILES.keys()), default=DEFAULT_PROFILE)
    p.add_argument("--config-file", help="JSON file with config overrides "
                                          "(can include a 'confidence_weights' object)")
    p.add_argument("-o", "--output-dir", default="output")
    p.add_argument("--threads", type=int, default=None)
    p.add_argument("--max-depth", type=int, default=None)
    p.add_argument("--perm-limit", type=int, default=None)
    p.add_argument("--max-recursion-rounds", type=int, default=None)
    p.add_argument("--recursion-threads", type=int, default=None,
                    help="Parallel workers for the recursive-enumeration stage (deliberately "
                         "lower than --threads by default since it hits external rate-limited "
                         "APIs like crt.sh). Was the fix for whole-hour stalls on big domains "
                         "-- this stage used to run fully sequential.")
    p.add_argument("--max-recursion-frontier", type=int, default=None,
                    help="Cap how many hosts get expanded in a single recursion round "
                         "(the rest stay validated, just aren't recursed into this run). "
                         "Pass 0 to disable the cap entirely.")
    p.add_argument("--source-threads", type=int, default=None,
                    help="Parallel workers for stage 1 (querying all 19 passive sources). "
                         "Was the fix for the biggest single contributor to hours-long runs "
                         "-- all sources used to be queried one at a time, serially.")
    p.add_argument("--recursion-round-timeout", type=int, default=None,
                    help="Hard ceiling (seconds) for a single recursion round -- if a handful "
                         "of (host, source) calls are still running past this (e.g. one host "
                         "sharing a wildcard cert with thousands of unrelated crt.sh entries), "
                         "the round continues with whatever finished rather than waiting "
                         "indefinitely. This is what actually fixes 'stuck for hours' -- "
                         "parallelism alone doesn't help if the slowest single call never returns.")
    p.add_argument("--source-stage-timeout", type=int, default=None,
                    help="Same hard-ceiling idea as --recursion-round-timeout, but for stage 1 "
                         "(passive source collection).")
    p.add_argument("--record-types", default=None,
                    help="Comma-separated DNS record types, e.g. A,AAAA,CNAME,MX,TXT,NS")
    p.add_argument("--no-permutations", action="store_true")
    p.add_argument("--active-recursion", action="store_true",
                    help="Also expand recursion via live JS/CSP scraping on discovered "
                         "hosts (not just passive OSINT APIs). Off by default.")
    p.add_argument("--resume", action="store_true",
                    help="Resume from the last completed stage instead of wiping the "
                         "domain's output dir and starting over (see 'Auto-fresh output' "
                         "below).")
    p.add_argument("--fresh", action="store_true",
                    help="No-op / kept for backward compatibility -- wiping the domain's "
                         "output dir before a run is now the DEFAULT behavior whenever "
                         "--resume isn't passed.")
    p.add_argument("--keep-checkpoints", action="store_true",
                    help="Don't auto-delete output/<domain>/checkpoints/ after a successful run")
    p.add_argument("--minimal", action="store_true",
                    help="After each run, delete everything except the final report in "
                         "txt (txt/final_hosts.txt) and JSON (reports/report.json) form -- "
                         "removes per-stage json/, extra txt files, report.csv/.html/.md, "
                         "cache.sqlite3, intel.sqlite3, metadata.json, checkpoints/ and "
                         "logs/ (keeps diff.json/diff.md if --diff was also used). Implies "
                         "--no-intel-db.")
    p.add_argument("--no-intel-db", action="store_true",
                    help="Skip writing this run into intel.sqlite3")
    p.add_argument("--diff", metavar="SOURCE", default=None,
                    help="Compare each domain's final hosts against a previous run. "
                         "SOURCE is either a path to an old reports/report.json (only "
                         "sensible with a single domain), or the literal 'auto' to diff "
                         "each domain against its own most recent prior run in intel.sqlite3.")
    p.add_argument("--list-plugins", action="store_true")
    p.add_argument("-v", "--verbose", action="store_true",
                    help="DEBUG-level console logging.")
    p.add_argument("--debug", action="store_true",
                    help="Like --verbose, plus full tracebacks (not just the message) for "
                         "every source that fails, logged both to console and logs/run.log.")
    p.add_argument("--quiet", action="store_true",
                    help="WARNING-level only -- suppresses per-source/per-host progress "
                         "noise, still shows warnings, errors, and the final summary. "
                         "Overridden by --verbose/--debug if both are passed.")

    for internal_name, (flag, _env) in KEY_FLAGS.items():
        p.add_argument(flag, dest=_flag_to_dest(flag), default=None)

    return p


def list_plugins(api_keys: dict) -> None:
    sources = instantiate_all()
    ctx = SourceContext(config={}, cache=None, api_keys=api_keys)
    print(f"{'name':<18} {'confidence':<10} available")
    print("-" * 47)
    for name, src in sorted(sources.items()):
        avail = "yes" if src.available(ctx) else "no (missing key/binary)"
        print(f"{name:<18} {src.confidence:<10} {avail}")


def _run_diff(args: argparse.Namespace, domain: str, report: dict, out_dir: str,
              intel_db: IntelDB | None, previous_hosts_before_store: set[str] | None) -> None:
    if args.diff == "auto":
        old_hosts = previous_hosts_before_store
        if old_hosts is None:
            logging.info(f"[diff:{domain}] no prior run found for this domain in "
                         "intel.sqlite3 -- nothing to diff against yet (first stored run).")
            return
    else:
        old_hosts = diff.load_hosts_from_report_json(args.diff)

    new_hosts = {h["host"] for h in report["hosts"]}
    d = diff.compute_diff(old_hosts, new_hosts)
    diff.write_diff_files(d, Path(out_dir))
    logging.info(f"[diff:{domain}] " + diff.render_diff_text(d).replace("\n", f"\n[diff:{domain}] "))


def _run_one_domain(args: argparse.Namespace, domain: str, out_dir: str, cfg: dict,
                     api_keys: dict, record_types: list[str] | None) -> int:
    """Guards `_run_one_domain_inner` with a PID-based lock on `out_dir`.

    Why: auto-fresh wipes `out_dir` at the start of every non-resumed run.
    If a second instance is pointed at the same `out_dir` (easy to do by
    accident -- the default is always just "output" unless you pass -o or
    use -dL batch mode) while a first one is still mid-run, the second
    instance's wipe destroys the first one's in-progress cache.sqlite3,
    checkpoints, and partial files out from under it -- silent corruption,
    not a clean error. This lock turns that into a clear, immediate refusal
    instead."""
    out_path = Path(out_dir)
    lock_path = out_path / ".recon.lock"

    if lock_path.exists():
        try:
            existing_pid = int(lock_path.read_text().strip())
        except (ValueError, OSError):
            existing_pid = None

        alive = False
        if existing_pid:
            try:
                os.kill(existing_pid, 0)
                alive = True
            except OSError:
                alive = False

        if alive:
            logging.error(
                f"[{domain}] refusing to run: another instance (pid {existing_pid}) is "
                f"already using '{out_dir}'. Running two instances against the same output "
                f"dir at once corrupts each other's cache/checkpoints. Use a different "
                f"-o for this domain, or -dL/--domain-list to scan multiple domains safely "
                f"(each gets its own subfolder)."
            )
            return 3
        else:
            logging.warning(f"[{domain}] found a stale lock (pid {existing_pid} not running) "
                            "-- removing it and continuing.")
            lock_path.unlink(missing_ok=True)

    if not args.resume:
        shutil.rmtree(out_dir, ignore_errors=True)
    out_path.mkdir(parents=True, exist_ok=True)
    lock_path.write_text(str(os.getpid()))

    try:
        return _run_one_domain_inner(args, domain, out_dir, cfg, api_keys, record_types)
    finally:
        lock_path.unlink(missing_ok=True)


def _run_one_domain_inner(args: argparse.Namespace, domain: str, out_dir: str, cfg: dict,
                           api_keys: dict, record_types: list[str] | None) -> int:
    """Runs the full pipeline for a single domain against `out_dir`. Returns
    a process-style exit code (0 ok, 130 interrupted). Called only through
    `_run_one_domain`, which holds the output-dir lock around this."""
    file_handler = _attach_file_logger(out_dir)
    try:
        logging.info(f"=== sazzad007 v{VERSION} started for: {domain} (profile={args.profile}) "
                     f"-> {out_dir}/ ===")
        logging.info("Scope reminder: only run this against domains you own or are explicitly "
                     "authorized to test.")

        pipeline = Pipeline(
            domain=domain, out_dir=out_dir, config=cfg, api_keys=api_keys,
            resume=args.resume, disable_permutations=args.no_permutations,
            record_types=record_types,
        )

        try:
            report = pipeline.run()
        except KeyboardInterrupt:
            completed = sorted(pipeline.stage_snapshots.keys())
            logging.warning(f"[interrupted:{domain}] run cancelled by user (Ctrl+C).")
            if completed:
                logging.warning(f"[interrupted:{domain}] stages completed and checkpointed: {completed}")
                logging.warning(f"[interrupted:{domain}] resume with: python3 run.py -d {domain} "
                                f"--profile {args.profile} -o {out_dir} --resume")
            else:
                logging.warning(f"[interrupted:{domain}] no stage completed yet -- nothing to resume from.")
            return 130

        exporters.write_all(report, out_dir, profile=args.profile, max_depth=cfg.get("max_depth"),
                             pipeline=pipeline)

        intel_db = None
        previous_hosts = None
        skip_intel_db = args.no_intel_db or args.minimal
        if not skip_intel_db:
            intel_db = IntelDB(str(Path(out_dir) / "intel.sqlite3"))
            if args.diff == "auto":
                previous_hosts = diff.load_hosts_from_intel_db(intel_db, domain)
            intel_db.store_run(report, profile=args.profile)

        if args.diff == "auto" and skip_intel_db:
            logging.warning(f"[diff:{domain}] --diff auto needs the intel DB, but it's disabled "
                            "here (--minimal implies --no-intel-db) -- skipping diff. Pass a "
                            "report.json path to --diff instead, or drop --minimal/--no-intel-db.")
        elif args.diff:
            _run_diff(args, domain, report, out_dir, intel_db, previous_hosts)

        if intel_db is not None:
            intel_db.close()

        if args.minimal:
            # detach + close the file handler FIRST -- cleanup_to_minimal
            # deletes logs/, and we don't want to delete a file we still
            # have open (harmless on Linux, but avoid it for portability).
            _detach_file_logger(file_handler)
            file_handler = None
            exporters.cleanup_to_minimal(out_dir)
        elif not args.keep_checkpoints:
            exporters.cleanup_intermediate(out_dir)

        if args.minimal:
            logging.info(f"[done:{domain}] final report (txt)  : {out_dir}/txt/final_hosts.txt")
            logging.info(f"[done:{domain}] final report (json)  : {out_dir}/reports/report.json")
            logging.info(f"[done:{domain}] --minimal: everything else was deleted.")
        else:
            logging.info(f"[done:{domain}] final hostnames (txt) : {out_dir}/txt/final_hosts.txt")
            logging.info(f"[done:{domain}] per-stage JSON        : {out_dir}/json/*.json")
            logging.info(f"[done:{domain}] JSON report           : {out_dir}/reports/report.json")
            logging.info(f"[done:{domain}] CSV report            : {out_dir}/reports/report.csv")
            logging.info(f"[done:{domain}] HTML report           : {out_dir}/reports/report.html")
            logging.info(f"[done:{domain}] Markdown report       : {out_dir}/reports/report.md")
            if not skip_intel_db:
                logging.info(f"[done:{domain}] intel DB              : {out_dir}/intel.sqlite3")
        logging.info(f"[done:{domain}] final validated hosts: {report['counts']['final_validated_hosts']}")
        logging.info(f"\n[{domain}]\n" + exporters.format_provider_summary(report))
        return 0
    finally:
        _detach_file_logger(file_handler)


def _setup_console_logging(args: argparse.Namespace) -> None:
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)  # handlers filter; root lets everything through
    if args.debug or args.verbose:
        console_level = logging.DEBUG
    elif args.quiet:
        console_level = logging.WARNING
    else:
        console_level = logging.INFO

    handler = logging.StreamHandler()
    handler.setLevel(console_level)
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    root_logger.addHandler(handler)


def _attach_file_logger(out_dir: str) -> logging.FileHandler:
    """Creates output/logs/run_<timestamp>.log for this domain's run and
    attaches it to the root logger at DEBUG level, ALWAYS capturing full
    detail regardless of console verbosity (--quiet still gets a complete
    log on disk). Returns the handler so the caller can remove/close it
    (e.g. before --minimal deletes logs/, or before starting the next
    domain in a batch)."""
    logs_dir = Path(out_dir) / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    log_path = logs_dir / f"run_{int(time.time())}.log"
    handler = logging.FileHandler(log_path, encoding="utf-8")
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    logging.getLogger().addHandler(handler)
    logging.info(f"[log] full debug log for this run: {log_path}")
    return handler


def _detach_file_logger(handler: logging.FileHandler | None) -> None:
    if handler is None:
        return
    logging.getLogger().removeHandler(handler)
    handler.close()


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    _setup_console_logging(args)

    api_keys = _resolve_api_keys(args)

    if args.list_plugins:
        list_plugins(api_keys)
        return 0

    domains = _resolve_domains(args)
    if not domains:
        parser.error("--domain/-d or --domain-list/-dL is required (or use --list-plugins)")

    mode_parts = ["Passive"]
    if args.active_recursion:
        mode_parts.append("Active")
    mode_parts.append("Recursive")
    banner.print_mr_cool_banner(
        version=VERSION,
        python_version=platform.python_version(),
        mode=" \u2022 ".join(mode_parts),
    )

    cfg = load_profile(args.profile)
    if args.config_file:
        cfg = merge_config_file(cfg, args.config_file)
    cfg = apply_cli_overrides(cfg, args)
    cfg["active_recursion"] = bool(args.active_recursion)
    cfg["debug"] = bool(args.debug)
    cfg["quiet"] = bool(args.quiet)

    record_types = args.record_types.split(",") if args.record_types else None

    batch = len(domains) > 1
    if batch:
        logging.info(f"=== batch mode: {len(domains)} domain(s) queued: {domains} ===")

    results: dict[str, int] = {}
    for domain in domains:
        out_dir = str(Path(args.output_dir) / domain) if batch else args.output_dir
        try:
            rc = _run_one_domain(args, domain, out_dir, cfg, api_keys, record_types)
        except KeyboardInterrupt:
            logging.warning(f"[interrupted:{domain}] cancelled by user (Ctrl+C) outside the "
                            "main pipeline stages -- partial output/lock already cleaned up.")
            rc = 130
        results[domain] = rc
        if rc == 130:
            logging.warning("[batch] stopping remaining domains after interruption.")
            break

    if batch:
        logging.info("=== Batch summary ===")
        for domain, rc in results.items():
            status = "OK" if rc == 0 else ("INTERRUPTED" if rc == 130 else f"FAILED ({rc})")
            logging.info(f"  {domain:<30} {status}")

    logging.info("=== Pipeline complete ===")
    if any(rc == 130 for rc in results.values()):
        return 130
    return 0
