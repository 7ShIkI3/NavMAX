"""
CLI NavMAX — point d'entrée console.
"""

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
        from navmax.scanner import tcp_connect_scan, parse_ports
        from navmax.core.logging import setup_logging, get_logger

        setup_logging()
        logger = get_logger(__name__)

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
            print(f"\n{'='*60}")
            print(f"  Cible : {target}")
            print(f"  Ports scannés : {len(ports_list)}")
            print(f"  Ports ouverts : {len(open_ports)}")
            print(f"{'='*60}")
            for r in open_ports:
                service = f" [{r.service}]" if r.service else ""
                banner = f" — {r.banner[:60]}" if r.banner else ""
                print(f"  {r.port:>6}/{r.protocol:<4} {r.state:<8}{service}{banner}")
            if not open_ports:
                print("  Aucun port ouvert détecté.")
            print()

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
        from navmax import __version__
        print(f"NavMAX v{__version__}")
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
    intercept: bool = typer.Option(False, "--intercept", "-i", help="Activer l'interception dès le démarrage"),
) -> None:
    """Démarre le proxy HTTP/HTTPS MITM (Burp-like)."""
    try:
        import asyncio
        from navmax.proxy import ProxyServer, Interceptor
        from navmax.core.logging import setup_logging, get_logger

        setup_logging()
        logger = get_logger(__name__)

        interceptor = Interceptor()
        interceptor.intercept_enabled = intercept
        server = ProxyServer(host=host, port=port, interceptor=interceptor)

        print(f"NavMAX Proxy démarré sur {host}:{port}")
        print(f"Interception : {'ON' if intercept else 'OFF'} (mode transparent)")
        print(f"Configurez votre navigateur : HTTP/HTTPS proxy = {host}:{port}")
        print(f"CA certificate : %USERPROFILE%\\.navmax\\certs\\navmax_ca_cert.pem")
        print("Ctrl+C pour arrêter\n")

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
        from navmax.proxy import WebScanner
        from navmax.core.logging import setup_logging

        setup_logging()

        async def _run() -> None:
            scanner = WebScanner()
            vulns = await scanner.scan_url(url=url, method=method)
            await scanner.close()

            print(f"\n{'='*60}")
            print(f"  Scan web : {url}")
            print(f"  Vulnérabilités : {len(vulns)}")
            print(f"{'='*60}")
            if vulns:
                for v in vulns:
                    print(f"\n  [{v.severity.upper()}] {v.name}")
                    if v.parameter:
                        print(f"    Paramètre : {v.parameter}")
                    if v.payload:
                        print(f"    Payload   : {v.payload[:60]}")
                    print(f"    {v.description}")
            else:
                print("  Aucune vulnérabilité évidente détectée.")
            print()

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
    categories: str = typer.Option("xss,sqli", "--categories", "-c", help="xss,sqli,path_traversal,command_injection,xxe,ssti,overflow"),
    concurrency: int = typer.Option(10, "--concurrency", "-j"),
) -> None:
    """Fuzze une URL avec des payloads d'attaque."""
    try:
        import asyncio
        from navmax.proxy import Fuzzer
        from navmax.core.logging import setup_logging

        setup_logging()

        cats = [c.strip() for c in categories.split(",")]

        async def _run() -> None:
            fuzzer = Fuzzer(concurrency=concurrency, categories=cats)
            report = await fuzzer.fuzz_url(url=url, method=method)
            await fuzzer.close()

            print(f"\n{'='*60}")
            print(f"  Fuzzing : {url}")
            print(f"  Tests   : {report.total_tests}")
            print(f"  Durée   : {report.duration_ms:.0f}ms")
            print(f"  Anomalies : {report.anomaly_count}")
            print(f"{'='*60}")
            if report.anomalies:
                for a in report.anomalies[:20]:
                    print(f"\n  [{a.payload_category.upper()}] {a.anomaly}")
                    print(f"    Point  : {a.injection_point} → {a.parameter_name}")
                    print(f"    Payload: {a.payload[:60]}")
                    if a.evidence:
                        print(f"    Preuve : {a.evidence[:100]}")
            else:
                print("  Aucune anomalie détectée.")
            print()

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
    platform: str = typer.Option("", "--platform", "-p", help="Filtrer par plateforme (windows, linux, multi)"),
) -> None:
    """Liste ou recherche des exploits dans le catalogue."""
    try:
        from navmax.exploit import exploit_loader

        results = exploit_loader.search(
            query=query,
            platform=platform or None,
            limit=50,
        )

        print(f"\n{'='*60}")
        print(f"  Catalogue d'exploits : {len(results)} résultat(s)")
        print(f"{'='*60}")
        for r in results:
            cve_tag = f" [{r['cve']}]" if r['cve'] else ""
            print(f"\n  {r['name']}{cve_tag}")
            print(f"    Plateforme : {r['platform']} | Catégorie : {r['category']} | Rang : {r['rank']}")
            print(f"    {r['description'][:120]}")
        print()
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
        from navmax.exploit import exploit_loader, ExploitError

        async def _run() -> None:
            opts = {"RHOST": rhost}
            if rport > 0:
                opts["RPORT"] = rport
            instance = exploit_loader.instantiate(exploit_name, **opts)
            result, message = await instance.check()
            print(f"\n[{result.value.upper()}] {instance.name}")
            print(f"  {message}\n")

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
        from navmax.exploit import exploit_loader, ExploitError

        async def _run() -> None:
            opts = {"RHOST": rhost, "LHOST": lhost, "LPORT": lport}
            if rport > 0:
                opts["RPORT"] = rport
            instance = exploit_loader.instantiate(exploit_name, **opts)
            result, message = await instance.exploit()
            print(f"\n[{result.value.upper()}] {instance.name}")
            print(f"  {message}\n")

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
    payload_type: str = typer.Option("reverse_shell", "--type", "-t", help="reverse_shell, bind_shell"),
    payload_format: str = typer.Option("python", "--format", "-f", help="python, bash, powershell, cmd, netcat"),
    host: str = typer.Option("127.0.0.1", "--host", "-h"),
    port: int = typer.Option(4444, "--port", "-p"),
    encode: str = typer.Option("none", "--encode", "-e", help="none, base64, url, hex, xor"),
) -> None:
    """Génère un payload."""
    try:
        from navmax.exploit import generate_payload, PayloadType, PayloadFormat, EncoderType

        pt = PayloadType(payload_type)
        pf = PayloadFormat(payload_format)
        enc = EncoderType(encode)
        result = generate_payload(pt, pf, host, port, enc)

        print(f"\n{'='*60}")
        print(f"  {result.description}")
        print(f"{'='*60}")
        print(f"\n{result.code}\n")
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
        from navmax.exploit import Handler
        from navmax.core.logging import setup_logging, get_logger

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

            print(f"Listener {protocol.upper()} démarré sur {host}:{port}")
            print("En attente de connexions... (Ctrl+C pour arrêter)\n")

            try:
                while True:
                    session = await handler.wait_session(timeout=3600)
                    if session:
                        print(f"\n[+] Nouvelle session : {session.id}")
                        print(f"    Adresse : {session.remote_address}:{session.remote_port}")
                        output = await handler.send_command(session.id, "whoami && hostname")
                        print(f"    Info : {output.strip()[:200]}")
            except asyncio.CancelledError:
                pass

        try:
            asyncio.run(_run())
        except KeyboardInterrupt:
            logger.info("listener_interrompu")
            print("\nHandler arrêté.")
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
        from navmax.osint import OsintOrchestrator
        from navmax.core.logging import setup_logging

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

            print(f"\n{'='*60}")
            print(f"  Investigation : {target}")
            print(f"  Type          : {target_type}")
            print(f"  Entités       : {result['node_count']}")
            print(f"  Relations     : {result['edge_count']}")
            print(f"{'='*60}")
            for line in result["log"]:
                print(f"  {line}")

            if export == "cytoscape":
                import json
                graph_data = orch.export("cytoscape")
                print(f"\n--- GRAPHE (Cytoscape.js) ---")
                print(json.dumps(graph_data, indent=2, ensure_ascii=False)[:10000])
            elif export == "sigmajs":
                import json
                graph_data = orch.export("sigmajs")
                print(f"\n--- GRAPHE (Sigma.js) ---")
                print(json.dumps(graph_data, indent=2, ensure_ascii=False)[:10000])
            elif export == "json":
                print(f"\n--- GRAPHE (JSON) ---")
                print(orch.export("json")[:10000])
            print()

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
            print(f"\n  DNS : {domain} ({len(records)} enregistrements)")
            for r in records:
                extra = f" (priorité {r.priority})" if r.priority else ""
                print(f"    {r.type:<8} {r.value[:60]}{extra}")

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
                print(f"\n  WHOIS : {info.domain}")
                print(f"    Registrar      : {info.registrar}")
                print(f"    Création       : {info.creation_date}")
                print(f"    Expiration     : {info.expiration_date}")
                print(f"    Registrant     : {info.registrant_name}")
                print(f"    Organisation   : {info.registrant_org}")
                print(f"    Email          : {info.registrant_email}")
                print(f"    Pays           : {info.registrant_country}")
                print(f"    Name Servers   : {', '.join(info.name_servers[:5])}")
            else:
                print(f"\n  WHOIS : {domain} — inaccessible")

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
                print(f"\n  SSL : {host}:{port}")
                print(f"    Sujet          : {info.subject}")
                print(f"    Émetteur       : {info.issuer}")
                print(f"    Valide du      : {info.not_before}")
                print(f"    Valide jusqu'au: {info.not_after}")
                print(f"    Jours restants : {info.days_remaining}")
                print(f"    Valide         : {'Oui' if info.is_valid else 'Non'}")
                print(f"    SANs           : {', '.join(info.san[:10])}")
                print(f"    SHA256         : {info.fingerprint_sha256[:32]}...")
            else:
                print(f"\n  SSL : {host}:{port} — certificat inaccessible")

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
                ws = await mgr.create(name, description)
                await session.commit()
                print(f"Workspace créé : {ws.id}")
                print(f"  Nom    : {ws.name}")
                print(f"  Description : {ws.description or '-'}")

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
                    print("Aucun workspace.")
                    return
                print(f"\n{'='*60}")
                print(f"  Workspaces ({len(ws_list)})")
                print(f"{'='*60}")
                for w in ws_list:
                    tc = len(w.targets) if w.targets else 0
                    print(f"  [{w.id[:8]}] {w.name} ({tc} cibles)")
                    if w.description:
                        print(f"       {w.description[:80]}")

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
                    print(f"Workspace {workspace_id} supprimé.")
                else:
                    print(f"Workspace {workspace_id} introuvable.")
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
