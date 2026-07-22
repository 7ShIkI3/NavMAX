"""CLI NavMAX — point d'entrée console."""

import subprocess
from pathlib import Path

import typer

app = typer.Typer(
    name="navmax",
    help="Plateforme de cybersécurité unifiée pour agents IA",
    no_args_is_help=True,
)


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", "--host", "-h"),
    port: int = typer.Option(8443, "--port", "-p"),
    reload: bool = typer.Option(False, "--reload", "-r", help="Mode développement (auto-reload)"),
) -> None:
    """Démarre le serveur API NavMAX."""
    try:
        import uvicorn

        from navmax.core.logging import get_logger

        logger = get_logger(__name__)
        logger.info("démarrage_serveur", host=host, port=port)

        uvicorn.run(
            "navmax.api.app:app",
            host=host,
            port=port,
            reload=reload,
            log_level="info",
        )
        raise typer.Exit(0)
    except KeyboardInterrupt:
        typer.echo("\nInterrompu.", err=True)
        raise typer.Exit(0)
    except Exception as e:
        typer.echo(f"Erreur : {e}", err=True)
        raise typer.Exit(1)


@app.command()
def scan(
    target: str = typer.Argument(..., help="IP, domaine ou CIDR à scanner"),
    ports: str = typer.Option("1-1000", "--ports", "-p", help="Ports (ex: 22,80,443 ou 1-1000)"),
    timeout: float = typer.Option(2.0, "--timeout", "-t", help="Timeout par port en secondes"),
    concurrency: int = typer.Option(100, "--concurrency", "-c", help="Connexions simultanées max"),
) -> None:
    """Scan réseau rapide (TCP Connect) sans API."""
    try:
        import asyncio

        from navmax.core.logging import get_logger, setup_logging
        from navmax.scanner import parse_ports, tcp_connect_scan

        setup_logging()
        get_logger(__name__)

        ports_list = parse_ports(ports)
        if not ports_list:
            typer.echo("Erreur : aucun port valide spécifié.", err=True)
            raise typer.Exit(2)

        async def _run() -> None:
            results = await tcp_connect_scan(
                ip=target,
                ports=ports_list,
                timeout=timeout,
                max_concurrency=concurrency,
            )
            open_ports = [r for r in results if r.state == "open"]
            for r in open_ports:
                f" — {r.banner[:60]}" if r.banner else ""
            if not open_ports:
                pass

        asyncio.run(_run())
        raise typer.Exit(0)
    except typer.Exit:
        raise
    except KeyboardInterrupt:
        typer.echo("\nInterrompu.", err=True)
        raise typer.Exit(0)
    except Exception as e:
        typer.echo(f"Erreur : {e}", err=True)
        raise typer.Exit(1)


@app.command()
def version() -> None:
    """Affiche la version."""
    try:

        raise typer.Exit(0)
    except typer.Exit:
        raise
    except Exception as e:
        typer.echo(f"Erreur : {e}", err=True)
        raise typer.Exit(1)


@app.command()
def proxy(
    host: str = typer.Option("127.0.0.1", "--host", "-h"),
    port: int = typer.Option(8080, "--port", "-p"),
    intercept: bool = typer.Option(
        False, "--intercept", "-i", help="Activer l'interception dès le démarrage",
    ),
) -> None:
    """Démarre le proxy HTTP/HTTPS MITM (Burp-like)."""
    try:
        import asyncio

        from navmax.core.logging import get_logger, setup_logging
        from navmax.proxy import Interceptor, ProxyServer

        setup_logging()
        logger = get_logger(__name__)

        interceptor = Interceptor()
        interceptor.intercept_enabled = intercept
        server = ProxyServer(host=host, port=port, interceptor=interceptor)


        async def _run() -> None:
            await server.start()
            try:
                await asyncio.Event().wait()  # Bloque indéfiniment
            except asyncio.CancelledError:
                pass
            finally:
                await server.stop()

        try:
            asyncio.run(_run())
        except KeyboardInterrupt:
            logger.info("proxy_interrompu")
        raise typer.Exit(0)
    except typer.Exit:
        raise
    except KeyboardInterrupt:
        typer.echo("\nInterrompu.", err=True)
        raise typer.Exit(0)
    except Exception as e:
        typer.echo(f"Erreur : {e}", err=True)
        raise typer.Exit(1)


@app.command()
def webscan(
    url: str = typer.Argument(..., help="URL à scanner"),
    method: str = typer.Option("GET", "--method", "-m"),
) -> None:
    """Scanne une URL pour les vulnérabilités web."""
    try:
        import asyncio

        from navmax.core.logging import setup_logging
        from navmax.proxy import WebScanner

        setup_logging()

        async def _run() -> None:
            scanner = WebScanner()
            vulns = await scanner.scan_url(url=url, method=method)
            await scanner.close()

            if vulns:
                for v in vulns:
                    if v.parameter:
                        pass
                    if v.payload:
                        pass
            else:
                pass

        asyncio.run(_run())
        raise typer.Exit(0)
    except typer.Exit:
        raise
    except KeyboardInterrupt:
        typer.echo("\nInterrompu.", err=True)
        raise typer.Exit(0)
    except Exception as e:
        typer.echo(f"Erreur : {e}", err=True)
        raise typer.Exit(1)


@app.command()
def fuzz(
    url: str = typer.Argument(..., help="URL à fuzzer"),
    method: str = typer.Option("GET", "--method", "-m"),
    categories: str = typer.Option(
        "xss,sqli",
        "--categories",
        "-c",
        help="xss,sqli,path_traversal,command_injection,xxe,ssti,overflow",
    ),
    concurrency: int = typer.Option(10, "--concurrency", "-j"),
) -> None:
    """Fuzze une URL avec des payloads d'attaque."""
    try:
        import asyncio

        from navmax.core.logging import setup_logging
        from navmax.proxy import Fuzzer

        setup_logging()

        cats = [c.strip() for c in categories.split(",")]

        async def _run() -> None:
            fuzzer = Fuzzer(concurrency=concurrency, categories=cats)
            report = await fuzzer.fuzz_url(url=url, method=method)
            await fuzzer.close()

            if report.anomalies:
                for a in report.anomalies[:20]:
                    if a.evidence:
                        pass
            else:
                pass

        asyncio.run(_run())
        raise typer.Exit(0)
    except typer.Exit:
        raise
    except KeyboardInterrupt:
        typer.echo("\nInterrompu.", err=True)
        raise typer.Exit(0)
    except Exception as e:
        typer.echo(f"Erreur : {e}", err=True)
        raise typer.Exit(1)


@app.command()
def exploits(
    query: str = typer.Option("", "--search", "-s", help="Recherche par mot-clé"),
    platform: str = typer.Option(
        "", "--platform", "-p", help="Filtrer par plateforme (windows, linux, multi)",
    ),
) -> None:
    """Liste ou recherche des exploits dans le catalogue."""
    try:
        from navmax.exploit import exploit_loader

        results = exploit_loader.search(
            query=query,
            platform=platform or None,
            limit=50,
        )

        for r in results:
            f" [{r['cve']}]" if r["cve"] else ""
        raise typer.Exit(0)
    except typer.Exit:
        raise
    except KeyboardInterrupt:
        typer.echo("\nInterrompu.", err=True)
        raise typer.Exit(0)
    except Exception as e:
        typer.echo(f"Erreur : {e}", err=True)
        raise typer.Exit(1)


@app.command()
def check(
    exploit_name: str = typer.Argument(..., help="Nom de l'exploit"),
    rhost: str = typer.Option(..., "--rhost", "-r", help="Adresse IP cible"),
    rport: int = typer.Option(0, "--rport", "-p"),
) -> None:
    """Vérifie si une cible est vulnérable à un exploit."""
    try:
        import asyncio

        from navmax.exploit import exploit_loader

        async def _run() -> None:
            opts = {"RHOST": rhost}
            if rport > 0:
                opts["RPORT"] = rport
            instance = exploit_loader.instantiate(exploit_name, **opts)
            _result, _message = await instance.check()

        asyncio.run(_run())
        raise typer.Exit(0)
    except typer.Exit:
        raise
    except KeyboardInterrupt:
        typer.echo("\nInterrompu.", err=True)
        raise typer.Exit(0)
    except Exception as e:
        typer.echo(f"Erreur : {e}", err=True)
        raise typer.Exit(1)


@app.command()
def run_exploit(
    exploit_name: str = typer.Argument(..., help="Nom de l'exploit"),
    rhost: str = typer.Option(..., "--rhost", "-r", help="Adresse IP cible"),
    rport: int = typer.Option(0, "--rport", "-p"),
    lhost: str = typer.Option("127.0.0.1", "--lhost", "-l"),
    lport: int = typer.Option(4444, "--lport"),
) -> None:
    """Exécute un exploit contre une cible."""
    try:
        import asyncio

        from navmax.exploit import exploit_loader

        async def _run() -> None:
            opts = {"RHOST": rhost, "LHOST": lhost, "LPORT": lport}
            if rport > 0:
                opts["RPORT"] = rport
            instance = exploit_loader.instantiate(exploit_name, **opts)
            _result, _message = await instance.exploit()

        asyncio.run(_run())
        raise typer.Exit(0)
    except typer.Exit:
        raise
    except KeyboardInterrupt:
        typer.echo("\nInterrompu.", err=True)
        raise typer.Exit(0)
    except Exception as e:
        typer.echo(f"Erreur : {e}", err=True)
        raise typer.Exit(1)


@app.command()
def payload(
    payload_type: str = typer.Option(
        "reverse_shell", "--type", "-t", help="reverse_shell, bind_shell",
    ),
    payload_format: str = typer.Option(
        "python", "--format", "-f", help="python, bash, powershell, cmd, netcat",
    ),
    host: str = typer.Option("127.0.0.1", "--host", "-h"),
    port: int = typer.Option(4444, "--port", "-p"),
    encode: str = typer.Option("none", "--encode", "-e", help="none, base64, url, hex, xor"),
) -> None:
    """Génère un payload."""
    try:
        from navmax.exploit import EncoderType, PayloadFormat, PayloadType, generate_payload

        pt = PayloadType(payload_type)
        pf = PayloadFormat(payload_format)
        enc = EncoderType(encode)
        generate_payload(pt, pf, host, port, enc)

        raise typer.Exit(0)
    except typer.Exit:
        raise
    except ValueError as e:
        typer.echo(f"Erreur : {e}", err=True)
        raise typer.Exit(2)
    except KeyboardInterrupt:
        typer.echo("\nInterrompu.", err=True)
        raise typer.Exit(0)
    except Exception as e:
        typer.echo(f"Erreur : {e}", err=True)
        raise typer.Exit(1)


@app.command()
def listener(
    port: int = typer.Option(4444, "--port", "-p"),
    protocol: str = typer.Option("tcp", "--protocol", help="tcp | http"),
    host: str = typer.Option("0.0.0.0", "--host"),
) -> None:
    """Démarre un listener pour recevoir des connexions reverse."""
    try:
        import asyncio

        from navmax.core.logging import get_logger, setup_logging
        from navmax.exploit import Handler

        setup_logging()
        logger = get_logger(__name__)

        if protocol not in ("tcp", "http"):
            typer.echo(f"Erreur : protocole invalide '{protocol}' (tcp | http)", err=True)
            raise typer.Exit(2)

        handler = Handler()

        async def _run() -> None:
            if protocol == "tcp":
                await handler.start_tcp(host, port)
            else:
                await handler.start_http(host, port)


            try:
                while True:
                    session = await handler.wait_session(timeout=3600)
                    if session:
                        await handler.send_command(session.id, "whoami && hostname")
            except asyncio.CancelledError:
                pass

        try:
            asyncio.run(_run())
        except KeyboardInterrupt:
            logger.info("listener_interrompu")
        raise typer.Exit(0)
    except typer.Exit:
        raise
    except KeyboardInterrupt:
        typer.echo("\nInterrompu.", err=True)
        raise typer.Exit(0)
    except Exception as e:
        typer.echo(f"Erreur : {e}", err=True)
        raise typer.Exit(1)


@app.command()
def osint(
    target: str = typer.Argument(..., help="Domaine ou IP à investiguer"),
    target_type: str = typer.Option("domain", "--type", "-t", help="domain | ip"),
    depth: int = typer.Option(2, "--depth", "-d", help="Profondeur d'investigation (1-3)"),
    export: str = typer.Option("text", "--export", "-e", help="text | cytoscape | sigmajs | json"),
) -> None:
    """Investigation OSINT complète (DNS, WHOIS, SSL, Web, Graphe)."""
    try:
        import asyncio

        from navmax.core.logging import setup_logging
        from navmax.osint import OsintOrchestrator

        setup_logging()

        if depth < 1 or depth > 3:
            typer.echo("Erreur : la profondeur doit être entre 1 et 3.", err=True)
            raise typer.Exit(2)

        if target_type not in ("domain", "ip"):
            typer.echo(f"Erreur : type invalide '{target_type}' (domain | ip)", err=True)
            raise typer.Exit(2)

        async def _run() -> None:
            orch = OsintOrchestrator(max_depth=depth)
            result = await orch.investigate(target, target_type)

            for _line in result["log"]:
                pass

            if export == "cytoscape":

                orch.export("cytoscape")
            elif export == "sigmajs":

                orch.export("sigmajs")
            elif export == "json":
                pass

        asyncio.run(_run())
        raise typer.Exit(0)
    except typer.Exit:
        raise
    except KeyboardInterrupt:
        typer.echo("\nInterrompu.", err=True)
        raise typer.Exit(0)
    except Exception as e:
        typer.echo(f"Erreur : {e}", err=True)
        raise typer.Exit(1)


@app.command()
def dns(
    domain: str = typer.Argument(..., help="Domaine à résoudre"),
) -> None:
    """Résolution DNS d'un domaine."""
    try:
        import asyncio

        from navmax.osint import DnsCollector

        async def _run() -> None:
            records = await DnsCollector.lookup(domain)
            for _r in records:
                pass

        asyncio.run(_run())
        raise typer.Exit(0)
    except typer.Exit:
        raise
    except KeyboardInterrupt:
        typer.echo("\nInterrompu.", err=True)
        raise typer.Exit(0)
    except Exception as e:
        typer.echo(f"Erreur : {e}", err=True)
        raise typer.Exit(1)


@app.command()
def whois(
    domain: str = typer.Argument(..., help="Domaine à interroger"),
) -> None:
    """WHOIS d'un domaine."""
    try:
        import asyncio

        from navmax.osint import WhoisCollector

        async def _run() -> None:
            info = await WhoisCollector.lookup(domain)
            if info:
                pass
            else:
                pass

        asyncio.run(_run())
        raise typer.Exit(0)
    except typer.Exit:
        raise
    except KeyboardInterrupt:
        typer.echo("\nInterrompu.", err=True)
        raise typer.Exit(0)
    except Exception as e:
        typer.echo(f"Erreur : {e}", err=True)
        raise typer.Exit(1)


@app.command()
def cert(
    host: str = typer.Argument(..., help="Hôte (IP ou domaine)"),
    port: int = typer.Option(443, "--port", "-p"),
) -> None:
    """Certificat SSL/TLS d'un hôte."""
    try:
        import asyncio

        from navmax.osint import SslCollector

        async def _run() -> None:
            info = await SslCollector.get_cert(host, port)
            if info and info.subject:
                pass
            else:
                pass

        asyncio.run(_run())
        raise typer.Exit(0)
    except typer.Exit:
        raise
    except KeyboardInterrupt:
        typer.echo("\nInterrompu.", err=True)
        raise typer.Exit(0)
    except Exception as e:
        typer.echo(f"Erreur : {e}", err=True)
        raise typer.Exit(1)


# ---------------------------------------------------------------------------
# Installation / Désinstallation
# ---------------------------------------------------------------------------
_setup_app = typer.Typer(help="Installation / désinstallation système")
app.add_typer(_setup_app, name="setup")


@_setup_app.command("install")
def install_cmd(
    port: int = typer.Option(8443, "--port", "-p", help="Port du serveur"),
    dev_mode: bool = typer.Option(False, "--dev", "-d", help="Mode développement"),
    force: bool = typer.Option(False, "--force", "-f", help="Réinstallation forcée"),
    no_shortcut: bool = typer.Option(False, "--no-shortcut", help="Sans raccourci bureau"),
    no_start_menu: bool = typer.Option(False, "--no-start-menu", help="Sans menu Démarrer"),
) -> None:
    """Lance l'installation système de NavMAX (PowerShell)."""
    try:
        script_dir = Path(__file__).resolve().parent.parent / "scripts"
        install_ps1 = script_dir / "install.ps1"

        if not install_ps1.exists():
            typer.echo(
                f"Erreur : script introuvable : {install_ps1}", err=True,
            )
            raise typer.Exit(1)

        cmd = [
            "powershell.exe",
            "-ExecutionPolicy", "Bypass",
            "-File", str(install_ps1),
            "-Port", str(port),
        ]
        if dev_mode:
            cmd.append("-DevMode")
        if force:
            cmd.append("-Force")
        if no_shortcut:
            cmd.append("-NoShortcut")
        if no_start_menu:
            cmd.append("-NoStartMenu")

        typer.echo(f"Lancement de : install.ps1 -Port {port} ...")
        subprocess.run(cmd, check=True)
        raise typer.Exit(0)
    except typer.Exit:
        raise
    except subprocess.CalledProcessError:
        typer.echo("Erreur : l'installation a échoué.", err=True)
        raise typer.Exit(1)
    except Exception as e:
        typer.echo(f"Erreur : {e}", err=True)
        raise typer.Exit(1)


@_setup_app.command("uninstall")
def uninstall_cmd(
    keep_data: bool = typer.Option(False, "--keep-data", help="Conserver les données utilisateur"),
    keep_config: bool = typer.Option(False, "--keep-config", help="Conserver la configuration"),
    force: bool = typer.Option(False, "--force", "-f", help="Ne pas demander confirmation"),
) -> None:
    """Lance la désinstallation système de NavMAX (PowerShell)."""
    try:
        script_dir = Path(__file__).resolve().parent.parent / "scripts"
        uninstall_ps1 = script_dir / "uninstall.ps1"

        if not uninstall_ps1.exists():
            typer.echo(
                f"Erreur : script introuvable : {uninstall_ps1}", err=True,
            )
            raise typer.Exit(1)

        cmd = [
            "powershell.exe",
            "-ExecutionPolicy", "Bypass",
            "-File", str(uninstall_ps1),
        ]
        if keep_data:
            cmd.append("-KeepData")
        if keep_config:
            cmd.append("-KeepConfig")
        if force:
            cmd.append("-Force")

        typer.echo("Lancement de : uninstall.ps1 ...")
        subprocess.run(cmd, check=True)
        raise typer.Exit(0)
    except typer.Exit:
        raise
    except subprocess.CalledProcessError:
        typer.echo("Erreur : la désinstallation a échoué.", err=True)
        raise typer.Exit(1)
    except Exception as e:
        typer.echo(f"Erreur : {e}", err=True)
        raise typer.Exit(1)


if __name__ == "__main__":
    app()


# ---------------------------------------------------------------------------
# Workspace
# ---------------------------------------------------------------------------
_workspace_app = typer.Typer(help="Gestion des workspaces (projets d'investigation)")
app.add_typer(_workspace_app, name="workspace")


@_workspace_app.command("create")
def workspace_create(
    name: str = typer.Argument(..., help="Nom du workspace"),
    description: str = typer.Option("", "--description", "-d"),
) -> None:
    """Crée un nouveau workspace."""
    try:
        import asyncio

        from navmax.db.engine import async_session
        from navmax.workspace import WorkspaceManager

        if not name.strip():
            typer.echo("Erreur : le nom du workspace ne peut pas être vide.", err=True)
            raise typer.Exit(2)

        async def _run() -> None:
            async with async_session() as session:
                mgr = WorkspaceManager(session)
                await mgr.create(name, description)
                await session.commit()

        asyncio.run(_run())
        raise typer.Exit(0)
    except typer.Exit:
        raise
    except KeyboardInterrupt:
        typer.echo("\nInterrompu.", err=True)
        raise typer.Exit(0)
    except Exception as e:
        typer.echo(f"Erreur : {e}", err=True)


# ═══════════════════════════════════════════════════════════════════════════════
# Dark Triad — Multi-Agent Red Team
# ═══════════════════════════════════════════════════════════════════════════════
_dark_triad_app = typer.Typer(help="🜏 Dark Triad — missions multi-agents avec personnalités")
app.add_typer(_dark_triad_app, name="dark-triad")


@_dark_triad_app.command("mission")
def dark_triad_mission(
    objective: str = typer.Argument(..., help="Objectif de la mission en langage naturel"),
    persona: str = typer.Option("mach", "--persona", "-p", help="mach|narcissism|psychopathy"),
) -> None:
    """Lance une mission Dark Triad complète (planification + exécution multi-agent)."""
    import asyncio
    from navmax.dark_triad.bootstrap import run_mission

    async def _run() -> None:
        typer.echo(f"\n🜏 Dark Triad — {persona.upper()} MODE\n")
        typer.echo(f"Objectif : {objective}\n")
        result = await run_mission(objective, persona)
        typer.echo(f"\n✅ {result['completed']} phases OK / {result['failed']} failed ({result['duration_ms']}ms)")
        for p in result["phases"]:
            icon = "✅" if p["status"] == "completed" else "❌"
            typer.echo(f"  {icon} {p['name']} — {p['agent']} ({p['duration_ms']}ms)")
            if p.get("output"):
                for line in p["output"].split("\n")[:3]:
                    typer.echo(f"     {line[:120]}")

    try:
        asyncio.run(_run())
    except Exception as e:
        typer.echo(f"❌ Mission échouée : {e}", err=True)
        raise typer.Exit(1)


@_workspace_app.command("list")
def workspace_list() -> None:
    """Liste tous les workspaces."""
    try:
        import asyncio

        from navmax.db.engine import async_session
        from navmax.workspace import WorkspaceManager

        async def _run() -> None:
            async with async_session() as session:
                mgr = WorkspaceManager(session)
                ws_list = await mgr.list_all()
                if not ws_list:
                    return
                for w in ws_list:
                    len(w.targets) if w.targets else 0
                    if w.description:
                        pass

        asyncio.run(_run())
        raise typer.Exit(0)
    except typer.Exit:
        raise
    except KeyboardInterrupt:
        typer.echo("\nInterrompu.", err=True)
        raise typer.Exit(0)
    except Exception as e:
        typer.echo(f"Erreur : {e}", err=True)
        raise typer.Exit(1)


@_workspace_app.command("delete")
def workspace_delete(
    workspace_id: str = typer.Argument(..., help="ID du workspace"),
) -> None:
    """Supprime un workspace."""
    try:
        import asyncio

        from navmax.db.engine import async_session
        from navmax.workspace import WorkspaceManager

        async def _run() -> None:
            async with async_session() as session:
                mgr = WorkspaceManager(session)
                ok = await mgr.delete(workspace_id)
                await session.commit()
                if ok:
                    pass
                else:
                    raise typer.Exit(1)

        asyncio.run(_run())
        raise typer.Exit(0)
    except typer.Exit:
        raise
    except KeyboardInterrupt:
        typer.echo("\nInterrompu.", err=True)
        raise typer.Exit(0)
    except Exception as e:
        typer.echo(f"Erreur : {e}", err=True)
        raise typer.Exit(1)
