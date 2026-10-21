#!/usr/bin/env python3
"""LanScope —— 局域网设备管家。

用法：
  python lanscope.py scan [--json]                     一次性扫描全网段并输出结果
  python lanscope.py serve [--port N] [--no-browser]   启动 Web 控制台（默认）
  python lanscope.py recon <MAC|IP>                    对单台设备深度侦察
"""
from __future__ import annotations

import argparse
import json
import sys
import unicodedata
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from lanscope import APP_NAME_CN, __version__


def _pad(s: str, width: int) -> str:
    """按显示宽度补空格（中文按 2 列计），保证 GBK 控制台对齐。"""
    w = sum(2 if unicodedata.east_asian_width(c) in "WF" else 1 for c in s)
    return s + " " * max(0, width - w)


def cmd_scan(args) -> int:
    from lanscope.fingerprint import ensure_oui
    from lanscope.netinfo import detect_env
    from lanscope.patrol import Patrol
    from lanscope.store import Store

    try:
        env = detect_env()
    except RuntimeError as exc:
        print(f"错误：{exc}")
        return 1
    print(env.describe())
    print("MAC 厂商库：无缓存时先用内置精简库，IEEE 全量库后台自动更新。")
    ensure_oui(background=True)
    store = Store(args.db)
    patrol = Patrol(store, env)
    result = patrol.run_full_scan("manual")
    if result is None:
        print("扫描未能完成。")
        return 1
    devices = store.list_devices()
    if args.json:
        payload = {
            "scan": result,
            "devices": [
                {
                    "mac": d["mac"],
                    "ip": d["last_ip"],
                    "hostname": d["hostname"],
                    "vendor": d["vendor"],
                    "type": d["custom_type"] or d["device_type"],
                    "online": d["status"] == 1,
                    "known": bool(d["known"]),
                }
                for d in devices
            ],
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        _print_table(store, devices, result)
    unknown = [d for d in devices if not d["known"]]
    print(
        f"\n在线 {result['online']} 台｜已录入 {len(devices)} 台｜未标记已知 {len(unknown)} 台"
    )
    if unknown:
        print("提示：未标记的设备再次出现变化时会触发新设备告警；可在 Web 控制台中标记。")
    store.close()
    return 0


def _print_table(store, devices, result) -> None:
    print(f"\n扫描完成（耗时 {result['duration']} 秒，方式 {result['method']}）：")
    print(
        _pad("状态", 5)
        + _pad("IP", 16)
        + _pad("MAC", 19)
        + _pad("厂商", 22)
        + _pad("主机名", 22)
        + _pad("类型", 10)
        + "端口"
    )
    print("-" * 110)
    for d in devices:
        status = "●" if d["status"] == 1 else "○"
        vendor = (d["vendor"] or "")[:20]
        hostname = (d["custom_name"] or d["hostname"] or "")[:20]
        dtype = d["custom_type"] or d["device_type"] or "unknown"
        ports = ",".join(str(p) for p in store.latest_ports(d["mac"]))
        print(
            _pad(status, 5)
            + _pad(d["last_ip"] or "", 16)
            + _pad(d["mac"], 19)
            + _pad(vendor, 22)
            + _pad(hostname, 22)
            + _pad(dtype, 10)
            + ports
        )


def cmd_recon(args) -> int:
    from lanscope.recon import ReconRunner
    from lanscope.store import Store

    store = Store(args.db)
    target = (args.target or "").strip()
    mac = target.upper() if ":" in target else ""
    if not mac:
        for d in store.list_devices():
            if d["last_ip"] == target:
                mac = d["mac"]
                break
    if not mac or not store.device_exists(mac):
        print(f"错误：{target} 不在设备台账中（先跑一次 scan）。")
        store.close()
        return 1
    ip = store.get_device(mac)["last_ip"]
    print(f"目标：{mac}（{ip}）——全端口扫描约 10～120 秒…")
    runner = ReconRunner(store)
    report = runner.run(mac, ip)
    if report is None:
        print("侦察未能完成（可能已有侦察任务在跑）。")
        store.close()
        return 1
    _print_recon(report)
    store.close()
    return 0


def _print_recon(report) -> None:
    print(f"\n深度侦察报告：{report['ip']}（{report['mac']}）")
    skipped = ",".join(map(str, report.get("skipped_ports", [])))
    print(
        f"耗时 {report['duration']} 秒｜开放端口 {report['open_count']} 个"
        f"｜跳过端口 {skipped}（本机安全软件劫持，防假阳性）"
    )
    osinfo = report.get("os") or {}
    print(f"OS 猜测：{osinfo.get('guess') or '未知'}（{osinfo.get('basis') or '—'}）")
    findings = report.get("findings") or []
    if findings:
        print("\n风险发现：")
        for f in findings:
            ports = (
                f"（端口 {','.join(map(str, f['ports']))}）" if f.get("ports") else ""
            )
            print(f"  [{f['severity']}] {f['message']}{ports}")
    vulns = report.get("vulns") or []
    if vulns:
        print("\n漏洞签名命中：")
        for v in vulns:
            cve = f"{v['cve']} " if v.get("cve") else ""
            print(
                f"  [{v['severity']}] {cve}{v['name']}"
                f"——端口 {v['port']}｜证据：{v['evidence']}"
            )
    ports = report.get("ports") or []
    if ports:
        shown = ", ".join(
            str(p["port"]) + (f"({p['service']})" if p.get("service") else "")
            for p in ports[:40]
        )
        print(f"\n开放端口：{shown}")
    print(f"\nKali 衔接：{report.get('kali_hint', '')}")


def cmd_serve(args) -> int:
    from lanscope.server import LanScopeApp, run_server

    app = LanScopeApp(
        db_path=args.db, port=args.port, open_browser=not args.no_browser
    )
    run_server(app)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="lanscope", description=f"LanScope —— {APP_NAME_CN}"
    )
    parser.add_argument("--version", action="version", version=f"LanScope {__version__}")
    sub = parser.add_subparsers(dest="cmd")

    p_scan = sub.add_parser("scan", help="一次性扫描全网段并输出结果")
    p_scan.add_argument("--json", action="store_true", help="以 JSON 输出")
    p_scan.add_argument("--db", default=None, help="数据库路径（默认 data/lanscope.db）")

    p_recon = sub.add_parser("recon", help="对单台设备深度侦察（全端口＋指纹＋风险）")
    p_recon.add_argument("target", help="设备 MAC 或 IP（须已在台账中）")
    p_recon.add_argument("--db", default=None, help="数据库路径（默认 data/lanscope.db）")

    p_serve = sub.add_parser("serve", help="启动 Web 控制台")
    p_serve.add_argument("--port", type=int, default=8765, help="监听端口（默认 8765）")
    p_serve.add_argument("--no-browser", action="store_true", help="不自动打开浏览器")
    p_serve.add_argument("--db", default=None, help="数据库路径（默认 data/lanscope.db）")

    args = parser.parse_args()
    if args.cmd == "scan":
        return cmd_scan(args)
    if args.cmd == "recon":
        return cmd_recon(args)
    if args.cmd is None:
        args = p_serve.parse_args([])
    return cmd_serve(args)


if __name__ == "__main__":
    sys.exit(main())
