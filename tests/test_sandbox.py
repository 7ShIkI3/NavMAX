"""Tests du module sandbox Docker pour exploits."""
import pytest
from navmax.exploit.sandbox import (
    ExploitSandbox,
    SandboxResult,
    SandboxConfig,
    SandboxMode,
)


class TestSandboxConfig:
    """Tests de la configuration sandbox."""

    def test_default_config(self):
        config = SandboxConfig()
        assert config.image == "alpine:latest"
        assert config.memory_limit == "128m"
        assert config.cpu_limit == 0.5
        assert config.network_mode == SandboxMode.ISOLATED
        assert config.timeout == 30
        assert config.read_only_rootfs is True
        assert config.no_new_privileges is True
        assert config.cap_drop == ["ALL"]

    def test_custom_config(self):
        config = SandboxConfig(
            image="python:3.11-alpine",
            network_mode=SandboxMode.BRIDGE,
            timeout=60,
            memory_limit="256m",
        )
        assert config.image == "python:3.11-alpine"
        assert config.network_mode == SandboxMode.BRIDGE
        assert config.timeout == 60
        assert config.memory_limit == "256m"


class TestSandboxResult:
    """Tests du modèle de résultat."""

    def test_success_result(self):
        result = SandboxResult(
            success=True,
            exit_code=0,
            stdout="Hello World\n",
            execution_time=0.5,
            container_id="abc123",
        )
        assert result.success is True
        assert result.exit_code == 0
        assert result.stdout == "Hello World\n"
        assert result.error is None

    def test_error_result(self):
        result = SandboxResult(
            success=False,
            exit_code=1,
            stderr="command not found",
            error="Timeout dépassé",
        )
        assert result.success is False
        assert result.exit_code == 1
        assert result.error == "Timeout dépassé"


@pytest.mark.asyncio
class TestExploitSandbox:
    """Tests du sandbox (mock Docker indisponible)."""

    async def test_docker_unavailable(self):
        """En l'absence de Docker, run() doit retourner une erreur propre."""
        sandbox = ExploitSandbox()
        # Force la vérification à False
        sandbox._docker_available = False

        result = await sandbox.run("print('hello')")
        assert result.success is False
        assert "Docker" in (result.error or "")

    async def test_docker_version_unavailable(self):
        """check_docker_version doit retourner indisponible."""
        sandbox = ExploitSandbox()
        sandbox._docker_available = False
        info = await sandbox.check_docker_version()
        assert info["available"] == "false"
        assert info["version"] == ""
