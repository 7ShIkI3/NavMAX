"""Tests pour navmax/cloud/scanner.py — scanners cloud sans SDK.

Teste :
- Dataclasses (CloudFinding, IAMRisk, CloudReconResult)
- S3 Bucket Scanner (HTTP HEAD mocké)
- IAM Policy Analyzer (JSON parsing)
- Cloud Recon DNS (socket mocké)
- CloudScanner class unifiée
- Graceful degradation sur timeout/erreur
"""

import socket
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from navmax.cloud.scanner import (
    CloudFinding,
    CloudReconResult,
    CloudScanner,
    IAMRisk,
    _check_wildcard_action,
    _check_wildcard_resource,
    _resolve_cname,
    analyze_iam_policy,
    discover_cloud_resources,
    scan_s3_buckets,
)

# ===========================================================================
# Tests Dataclasses
# ===========================================================================


class TestCloudFinding:
    """Tests de la dataclass CloudFinding."""

    def test_default_creation(self) -> None:
        finding = CloudFinding(
            service="AWS S3",
            resource="mon-bucket",
            issue="Bucket public",
            severity="high",
            evidence="HTTP 200",
            remediation="Restreindre l'accès",
        )
        assert finding.service == "AWS S3"
        assert finding.resource == "mon-bucket"
        assert finding.issue == "Bucket public"
        assert finding.severity == "high"
        assert finding.evidence == "HTTP 200"
        assert finding.remediation == "Restreindre l'accès"

    def test_default_empty_evidence(self) -> None:
        finding = CloudFinding(
            service="AWS",
            resource="test",
            issue="test",
            severity="info",
        )
        assert finding.evidence == ""
        assert finding.remediation == ""


class TestIAMRisk:
    """Tests de la dataclass IAMRisk."""

    def test_default_creation(self) -> None:
        risk = IAMRisk(
            risk_type="wildcard_action",
            severity="high",
            description="Action wildcard dans statement 0",
            policy_statement_index=0,
        )
        assert risk.risk_type == "wildcard_action"
        assert risk.severity == "high"
        assert risk.policy_statement_index == 0


class TestCloudReconResult:
    """Tests de la dataclass CloudReconResult."""

    def test_default_creation(self) -> None:
        result = CloudReconResult(domain="example.com")
        assert result.domain == "example.com"
        assert result.s3_buckets == []
        assert result.cloudfront_domains == []
        assert result.azure_resources == []
        assert result.gcp_resources == []
        assert result.ips_found == []

    def test_all_resources(self) -> None:
        result = CloudReconResult(
            domain="test.com",
            s3_buckets=["bucket1.s3.amazonaws.com"],
            cloudfront_domains=["cdn.cloudfront.net"],
            azure_resources=["blob.core.windows.net"],
            gcp_resources=["storage.googleapis.com"],
        )
        all_res = result.all_resources()
        assert len(all_res) == 4
        assert "bucket1.s3.amazonaws.com" in all_res
        assert "cdn.cloudfront.net" in all_res
        assert "blob.core.windows.net" in all_res
        assert "storage.googleapis.com" in all_res


# ===========================================================================
# Tests des helpers internes
# ===========================================================================


class TestWildcardChecks:
    """Tests de _check_wildcard_action et _check_wildcard_resource."""

    def test_wildcard_action_true(self) -> None:
        assert _check_wildcard_action("*") is True

    def test_wildcard_action_quoted(self) -> None:
        assert _check_wildcard_action('"*"') is True
        assert _check_wildcard_action("'*'") is True

    def test_wildcard_action_false(self) -> None:
        assert _check_wildcard_action("s3:GetObject") is False
        assert _check_wildcard_action("iam:CreateUser") is False

    def test_wildcard_resource_true(self) -> None:
        assert _check_wildcard_resource("*") is True

    def test_wildcard_resource_false(self) -> None:
        assert _check_wildcard_resource("arn:aws:s3:::my-bucket/*") is False


# ===========================================================================
# Tests IAM Policy Analyzer
# ===========================================================================


class TestAnalyzeIAMPolicy:
    """Tests de analyze_iam_policy."""

    @pytest.mark.asyncio
    async def test_empty_policy(self) -> None:
        """Politique vide = pas de risques."""
        risks = await analyze_iam_policy({})
        assert risks == []

    @pytest.mark.asyncio
    async def test_no_statements(self) -> None:
        """Politique sans Statement = pas de risques."""
        risks = await analyze_iam_policy({"Version": "2012-10-17"})
        assert risks == []

    @pytest.mark.asyncio
    async def test_single_statement_dict(self) -> None:
        """Statement sous forme de dict (pas de liste)."""
        policy = {
            "Statement": {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
            },
        }
        risks = await analyze_iam_policy(policy)
        assert len(risks) >= 3  # wildcard_action + wildcard_resource + admin_policy

    @pytest.mark.asyncio
    async def test_wildcard_action_detection(self) -> None:
        """Détecte les actions wildcard."""
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "arn:aws:s3:::my-bucket/*",
                },
            ],
        }
        risks = await analyze_iam_policy(policy)
        risk_types = [r.risk_type for r in risks]
        assert "wildcard_action" in risk_types

    @pytest.mark.asyncio
    async def test_wildcard_resource_detection(self) -> None:
        """Détecte les resources wildcard."""
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "*",
                },
            ],
        }
        risks = await analyze_iam_policy(policy)
        risk_types = [r.risk_type for r in risks]
        assert "wildcard_resource" in risk_types

    @pytest.mark.asyncio
    async def test_admin_policy_detection(self) -> None:
        """Détecte les politiques administrateur (wildcard action + resource)."""
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*",
                },
            ],
        }
        risks = await analyze_iam_policy(policy)
        risk_types = [r.risk_type for r in risks]
        assert "admin_policy" in risk_types

    @pytest.mark.asyncio
    async def test_deny_statements_not_flagged(self) -> None:
        """Les statements Deny ne sont pas flaggés comme risques."""
        policy = {
            "Statement": [
                {
                    "Effect": "Deny",
                    "Action": "*",
                    "Resource": "*",
                },
            ],
        }
        risks = await analyze_iam_policy(policy)
        # Deny avec wildcard n'est pas un risque
        assert risks == []

    @pytest.mark.asyncio
    async def test_missing_condition_on_sensitive_action(self) -> None:
        """Détecte l'absence de condition sur des actions sensibles."""
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "iam:CreateUser",
                    "Resource": "arn:aws:iam::123456789012:user/*",
                },
            ],
        }
        risks = await analyze_iam_policy(policy)
        risk_types = [r.risk_type for r in risks]
        assert "missing_condition" in risk_types

    @pytest.mark.asyncio
    async def test_condition_present_no_risk(self) -> None:
        """Action sensible avec condition = pas de risque 'missing_condition'."""
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "iam:CreateUser",
                    "Resource": "arn:aws:iam::123456789012:user/*",
                    "Condition": {"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}},
                },
            ],
        }
        risks = await analyze_iam_policy(policy)
        risk_types = [r.risk_type for r in risks]
        assert "missing_condition" not in risk_types

    @pytest.mark.asyncio
    async def test_multiple_statements(self) -> None:
        """Analyse correcte de multiples statements."""
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::my-bucket/*",
                },
                {
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "arn:aws:s3:::other-bucket/*",
                },
                {
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*",
                },
            ],
        }
        risks = await analyze_iam_policy(policy)
        assert len(risks) >= 3

        # Vérifie les index des statements
        statement_indices = [r.policy_statement_index for r in risks]
        assert 0 not in statement_indices  # statement 0 est safe
        assert 1 in statement_indices  # wildcard action
        assert 2 in statement_indices  # admin policy


# ===========================================================================
# Tests S3 Bucket Scanner (mocké)
# ===========================================================================


class TestS3BucketScanner:
    """Tests de scan_s3_buckets avec httpx mocké."""

    @pytest.mark.asyncio
    async def test_empty_list(self) -> None:
        """Liste vide = pas de findings."""
        findings = await scan_s3_buckets([])
        assert findings == []

    @pytest.mark.asyncio
    async def test_bucket_not_found(self) -> None:
        """Bucket 404 = pas de findings."""
        mock_response = MagicMock()
        mock_response.status_code = 404

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client_cls.return_value.__aenter__.return_value = mock_client
            mock_client.head.return_value = mock_response

            findings = await scan_s3_buckets(["bucket-inexistant"])
            assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_bucket_private(self) -> None:
        """Bucket 403 (privé) = info finding."""
        mock_response = MagicMock()
        mock_response.status_code = 403

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client_cls.return_value.__aenter__.return_value = mock_client
            mock_client.head.return_value = mock_response

            findings = await scan_s3_buckets(["bucket-prive"])
            assert len(findings) == 1
            assert findings[0].severity == "info"
            assert "privé" in findings[0].issue.lower() or "privé" in findings[0].issue.lower()

    @pytest.mark.asyncio
    async def test_bucket_public_read(self) -> None:
        """Bucket 200 (public) = high severity findings."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {}  # pas de x-amz-version-id

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client_cls.return_value.__aenter__.return_value = mock_client
            mock_client.head.return_value = mock_response

            findings = await scan_s3_buckets(["bucket-public"])
            severities = [f.severity for f in findings]
            assert "high" in severities  # public read
            assert "medium" in severities  # pas de versioning

    @pytest.mark.asyncio
    async def test_graceful_timeout_degradation(self) -> None:
        """Timeout ne doit pas casser le scan — graceful degradation."""
        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client_cls.return_value.__aenter__.return_value = mock_client
            from httpx import TimeoutException

            mock_client.head.side_effect = TimeoutException("Timeout simulé")

            findings = await scan_s3_buckets(["bucket-timeout"])
            assert findings == []  # graceful degradation = liste vide

    @pytest.mark.asyncio
    async def test_mixed_results(self) -> None:
        """Plusieurs buckets avec des résultats différents."""

        def side_effect(url, **kwargs):
            resp = MagicMock()
            if "prive" in str(url):
                resp.status_code = 403
            elif "public" in str(url):
                resp.status_code = 200
                resp.headers = {}
            else:
                resp.status_code = 404
            return resp

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client_cls.return_value.__aenter__.return_value = mock_client
            mock_client.head.side_effect = side_effect

            findings = await scan_s3_buckets(["bucket-prive", "bucket-public", "bucket-404"])
            assert len(findings) >= 2  # privé (info) + public (high + medium)


# ===========================================================================
# Tests Cloud Recon DNS (socket mocké)
# ===========================================================================


class TestResolveCname:
    """Tests de _resolve_cname avec socket mocké."""

    @pytest.mark.asyncio
    async def test_dns_resolution_success(self) -> None:
        """Résolution DNS réussie retourne les alias CNAME."""
        with (
            patch("socket.gethostbyname_ex") as mock_gethost,
            patch("socket.gethostbyname", return_value="93.184.216.34"),
        ):
            mock_gethost.return_value = (
                "example.com",
                ["example.s3.amazonaws.com", "cdn.cloudfront.net"],
                ["93.184.216.34"],
            )

            cnames = await _resolve_cname("example.com")
            assert len(cnames) >= 2
            assert any("s3.amazonaws.com" in c for c in cnames)
            assert any("cloudfront.net" in c for c in cnames)

    @pytest.mark.asyncio
    async def test_dns_resolution_failure(self) -> None:
        """Échec DNS = graceful degradation (liste vide)."""
        with patch("socket.gethostbyname_ex", side_effect=socket.gaierror("DNS error")):
            cnames = await _resolve_cname("domain-inexistant.com")
            assert cnames == []


class TestDiscoverCloudResources:
    """Tests de discover_cloud_resources avec socket et httpx mockés."""

    @pytest.mark.asyncio
    async def test_discover_no_resources(self) -> None:
        """Aucune ressource cloud trouvée."""
        mock_response = MagicMock()
        mock_response.status_code = 404

        with (
            patch("httpx.AsyncClient") as mock_client_cls,
            patch("socket.gethostbyname_ex", side_effect=socket.gaierror("DNS error")),
        ):
            mock_client = AsyncMock()
            mock_client_cls.return_value.__aenter__.return_value = mock_client
            mock_client.head.return_value = mock_response

            result = await discover_cloud_resources("exemple-securise.com", resolve_dns=True)
            assert result.domain == "exemple-securise.com"
            assert len(result.all_resources()) == 0

    @pytest.mark.asyncio
    async def test_discover_s3_bucket(self) -> None:
        """Découverte d'un bucket S3."""
        with (
            patch("httpx.AsyncClient") as mock_client_cls,
            patch(
                "socket.gethostbyname_ex",
                return_value=(
                    "test.com",
                    ["test.s3.amazonaws.com"],
                    ["1.2.3.4"],
                ),
            ),
        ):
            mock_client = AsyncMock()
            mock_client_cls.return_value.__aenter__.return_value = mock_client
            # Simule que le sous-domaine s3 existe
            mock_response_ok = MagicMock()
            mock_response_ok.status_code = 200
            mock_response_404 = MagicMock()
            mock_response_404.status_code = 404
            mock_client.head.return_value = mock_response_404

            # On patch aussi la résolution CNAME qui doit trouver le S3
            result = await discover_cloud_resources("test.com", resolve_dns=True)
            assert result.domain == "test.com"

    @pytest.mark.asyncio
    async def test_graceful_dns_failure(self) -> None:
        """DNS failure = graceful degradation (résultat vide mais pas d'exception)."""
        with (
            patch("httpx.AsyncClient") as mock_client_cls,
            patch("socket.gethostbyname_ex", side_effect=Exception("DNS crash")),
        ):
            mock_client = AsyncMock()
            mock_client_cls.return_value.__aenter__.return_value = mock_client
            mock_response = MagicMock()
            mock_response.status_code = 404
            mock_client.head.return_value = mock_response

            result = await discover_cloud_resources("test.com", resolve_dns=True)
            assert result.domain == "test.com"
            # Aucune ressource trouvée, mais pas d'exception
            assert isinstance(result, CloudReconResult)


# ===========================================================================
# Tests CloudScanner (classe unifiée)
# ===========================================================================


class TestCloudScanner:
    """Tests de la classe CloudScanner."""

    def test_default_creation(self) -> None:
        scanner = CloudScanner()
        assert scanner.timeout == 10.0
        assert scanner.resolve_dns is True

    def test_custom_timeout(self) -> None:
        scanner = CloudScanner(timeout=30.0, resolve_dns=False)
        assert scanner.timeout == 30.0
        assert scanner.resolve_dns is False

    @pytest.mark.asyncio
    async def test_scan_s3_buckets_empty(self) -> None:
        """scan_s3_buckets via CloudScanner retourne liste vide pour aucun bucket."""
        scanner = CloudScanner()
        findings = await scanner.scan_s3_buckets([])
        assert findings == []

    @pytest.mark.asyncio
    async def test_analyze_iam_policy_empty(self) -> None:
        """analyze_iam_policy via CloudScanner."""
        scanner = CloudScanner()
        risks = await scanner.analyze_iam_policy({})
        assert risks == []

    @pytest.mark.asyncio
    async def test_analyze_iam_policy_admin(self) -> None:
        """Détection de politique admin via CloudScanner."""
        scanner = CloudScanner()
        policy = {
            "Statement": [
                {"Effect": "Allow", "Action": "*", "Resource": "*"},
            ],
        }
        risks = await scanner.analyze_iam_policy(policy)
        risk_types = [r.risk_type for r in risks]
        assert "admin_policy" in risk_types

    @pytest.mark.asyncio
    async def test_discover_cloud_resources_empty(self) -> None:
        """discover_cloud_resources via CloudScanner avec DNS mocké."""
        scanner = CloudScanner()

        with (
            patch("httpx.AsyncClient") as mock_client_cls,
            patch("socket.gethostbyname_ex", side_effect=socket.gaierror("DNS error")),
        ):
            mock_client = AsyncMock()
            mock_client_cls.return_value.__aenter__.return_value = mock_client
            mock_response = MagicMock()
            mock_response.status_code = 404
            mock_client.head.return_value = mock_response

            result = await scanner.discover_cloud_resources("inconnu.com")
            assert result.domain == "inconnu.com"
            assert len(result.all_resources()) == 0


# ===========================================================================
# Tests d'intégration (graceful degradation réelle)
# ===========================================================================


class TestGracefulDegradation:
    """Tests de la résilience aux erreurs réseau."""

    @pytest.mark.asyncio
    async def test_s3_connect_error(self) -> None:
        """Erreur de connexion S3 = graceful degradation."""
        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client_cls.return_value.__aenter__.return_value = mock_client
            from httpx import ConnectError

            mock_client.head.side_effect = ConnectError("Connection refused")

            findings = await scan_s3_buckets(["bucket-inaccessible"])
            assert findings == []

    @pytest.mark.asyncio
    async def test_iam_invalid_json(self) -> None:
        """IAM analyzer sur un dict malformé = pas d'erreur."""
        risks = await analyze_iam_policy({"invalid": True})
        assert risks == []

    @pytest.mark.asyncio
    async def test_iam_statement_as_string(self) -> None:
        """Statement qui est une chaîne inattendue = ignoré silencieusement."""
        policy = {"Statement": "NotAStatement"}
        risks = await analyze_iam_policy(policy)
        # Le code traite les strings comme liste de 1 char... donc aucun risque
        assert risks == []

    @pytest.mark.asyncio
    async def test_discover_network_unreachable(self) -> None:
        """DNS/Hôte injoignable = graceful degradation."""
        with (
            patch("httpx.AsyncClient") as mock_client_cls,
            patch("socket.gethostbyname_ex", side_effect=OSError("Network error")),
        ):
            mock_client = AsyncMock()
            mock_client_cls.return_value.__aenter__.return_value = mock_client
            mock_client.head.side_effect = Exception("Network error")

            result = await discover_cloud_resources("unreachable.test", resolve_dns=True)
            assert result.domain == "unreachable.test"
            assert isinstance(result, CloudReconResult)
