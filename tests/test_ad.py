"""
Tests pour le module Active Directory / LDAP.

Couvre : ADConfig, ADConnector (mocké), ADEnumerator (parsing), DomainMap.
"""

import pytest
from datetime import datetime

from navmax.ad.connector import (
    ADConfig,
    ADAuthMethod,
    ADSearchScope,
    ADUser,
    ADGroup,
    ADComputer,
    ADOU,
    ADGPO,
    ADDomain,
    ADTrust,
    ADConnectionError,
    ADAuthenticationError,
    parse_user_account_control,
    FUNCTIONAL_LEVEL_MAP,
    TRUST_DIRECTION_MAP,
    TRUST_TYPE_MAP,
)

from navmax.ad.enumerator import (
    ADEnumerator,
    DomainMap,
    EnumerationResult,
)


# ═══════════════════════════════════════════════════════════════
# ADConfig
# ═══════════════════════════════════════════════════════════════

class TestADConfig:
    def test_default_port_ssl(self):
        config = ADConfig(server="dc.local", domain="local", use_ssl=True)
        assert config.effective_port == 636

    def test_default_port_no_ssl(self):
        config = ADConfig(server="dc.local", domain="local", use_ssl=False)
        assert config.effective_port == 389

    def test_custom_port(self):
        config = ADConfig(server="dc.local", domain="local", port=3269)
        assert config.effective_port == 3269

    def test_base_dn_derivation(self):
        config = ADConfig(server="dc.local", domain="corp.internal.com")
        assert config.effective_base_dn == "DC=corp,DC=internal,DC=com"

    def test_base_dn_explicit(self):
        config = ADConfig(server="dc.local", domain="local",
                          base_dn="CN=Users,DC=local")
        assert config.effective_base_dn == "CN=Users,DC=local"


# ═══════════════════════════════════════════════════════════════
# ADUser — Properties
# ═══════════════════════════════════════════════════════════════

class TestADUserProperties:
    def test_enabled_user(self):
        u = ADUser(dn="CN=Test", sam_account_name="test",
                   user_account_control=512)  # NORMAL_ACCOUNT
        assert u.is_enabled is True
        assert u.is_admin is False
        assert u.is_kerberoastable is False
        assert u.is_asrep_roastable is False

    def test_disabled_user(self):
        u = ADUser(dn="CN=Test", sam_account_name="test",
                   user_account_control=514)  # NORMAL_ACCOUNT | ACCOUNTDISABLE
        assert u.is_enabled is False

    def test_admin_user(self):
        u = ADUser(dn="CN=Admin", sam_account_name="admin",
                   user_account_control=512, admin_count=1)
        assert u.is_admin is True

    def test_kerberoastable_user(self):
        u = ADUser(dn="CN=Svc", sam_account_name="svc",
                   user_account_control=512,
                   service_principal_names=["HTTP/svc.corp.local"])
        assert u.is_kerberoastable is True

    def test_asrep_roastable_user(self):
        u = ADUser(dn="CN=User", sam_account_name="user",
                   user_account_control=0x400000)  # DONT_REQ_PREAUTH
        assert u.is_asrep_roastable is True

    def test_delegation_user(self):
        u = ADUser(dn="CN=Del", sam_account_name="del",
                   user_account_control=0x80000)  # TRUSTED_FOR_DELEGATION
        assert u.is_trusted_for_delegation is True


# ═══════════════════════════════════════════════════════════════
# ADGroup — Properties
# ═══════════════════════════════════════════════════════════════

class TestADGroupProperties:
    def test_global_security(self):
        g = ADGroup(dn="CN=Test", sam_account_name="TestGroup",
                    group_type=-2147483646)  # Global Security
        assert g.scope == "global"
        assert g.is_security_group is True

    def test_universal_security(self):
        g = ADGroup(dn="CN=Test", sam_account_name="TestGroup",
                    group_type=-2147483640)  # Universal Security
        assert g.scope == "universal"

    def test_domain_local(self):
        g = ADGroup(dn="CN=Test", sam_account_name="TestGroup",
                    group_type=-2147483644)  # Domain Local Security
        assert g.scope == "domain_local"

    def test_distribution_group(self):
        g = ADGroup(dn="CN=Dist", sam_account_name="DistGroup",
                    group_type=2)  # Global Distribution
        assert g.is_security_group is False


# ═══════════════════════════════════════════════════════════════
# ADComputer — Properties
# ═══════════════════════════════════════════════════════════════

class TestADComputerProperties:
    def test_domain_controller(self):
        c = ADComputer(dn="CN=DC01", sam_account_name="DC01$",
                       user_account_control=0x2000)  # SERVER_TRUST_ACCOUNT
        assert c.is_domain_controller is True

    def test_workstation(self):
        c = ADComputer(dn="CN=WS01", sam_account_name="WS01$",
                       user_account_control=4096)  # WORKSTATION_TRUST
        assert c.is_domain_controller is False

    def test_disabled_computer(self):
        c = ADComputer(dn="CN=OLD", sam_account_name="OLD$",
                       user_account_control=4098)  # WORKSTATION | ACCOUNTDISABLE
        assert c.is_enabled is False


# ═══════════════════════════════════════════════════════════════
# parse_user_account_control
# ═══════════════════════════════════════════════════════════════

class TestParseUAC:
    def test_normal_account(self):
        flags = parse_user_account_control(512)
        assert flags["NORMAL_ACCOUNT"] is True
        assert flags["ACCOUNTDISABLE"] is False
        assert flags["DONT_REQ_PREAUTH"] is False

    def test_disabled_account(self):
        flags = parse_user_account_control(514)
        assert flags["NORMAL_ACCOUNT"] is True
        assert flags["ACCOUNTDISABLE"] is True

    def test_combined_flags(self):
        flags = parse_user_account_control(0x10000 | 0x400000)
        assert flags["DONT_EXPIRE_PASSWORD"] is True
        assert flags["DONT_REQ_PREAUTH"] is True

    def test_no_flags_set(self):
        flags = parse_user_account_control(0)
        assert all(v is False for v in flags.values())


# ═══════════════════════════════════════════════════════════════
# Timestamp Parsing (static methods)
# ═══════════════════════════════════════════════════════════════

class TestTimestampParsing:
    def test_windows_timestamp_zero(self):
        assert ADEnumerator._parse_windows_timestamp(0) is None

    def test_windows_timestamp_never(self):
        assert ADEnumerator._parse_windows_timestamp(9223372036854775807) is None

    def test_windows_timestamp_none(self):
        assert ADEnumerator._parse_windows_timestamp(None) is None

    def test_ldap_timestamp_valid(self):
        dt = ADEnumerator._parse_ldap_timestamp("20240615083045.0Z")
        assert dt == datetime(2024, 6, 15, 8, 30, 45)

    def test_ldap_timestamp_none(self):
        assert ADEnumerator._parse_ldap_timestamp(None) is None

    def test_windows_timestamp_known_date(self):
        # 2024-06-15T08:30:45 UTC
        # Convert to Windows FILETIME:
        # unix_ts = 1718436645
        # epoch_diff = 116444736000000000
        # filetime = (unix_ts * 10000000) + epoch_diff
        # = 17184366450000000 + 116444736000000000 = 133629102450000000
        ts = 133629102450000000
        result = ADEnumerator._parse_windows_timestamp(ts)
        assert result is not None
        assert result.year == 2024
        assert result.month == 6
        assert result.day == 15


# ═══════════════════════════════════════════════════════════════
# ADEnumerator — Raw Entry Parsing
# ═══════════════════════════════════════════════════════════════

class TestEnumeratorParsing:
    def setup_method(self):
        self.enumerator = ADEnumerator.__new__(ADEnumerator)
        self.enumerator._errors = []

    def test_parse_user_basic(self):
        entry = {
            "dn": "CN=John Doe,CN=Users,DC=corp,DC=local",
            "attributes": {
                "sAMAccountName": ["jdoe"],
                "userPrincipalName": ["jdoe@corp.local"],
                "displayName": ["John Doe"],
                "mail": ["john@corp.local"],
                "title": ["Manager"],
                "department": ["IT"],
                "memberOf": [
                    "CN=Domain Users,CN=Users,DC=corp,DC=local",
                    "CN=IT Staff,OU=Groups,DC=corp,DC=local",
                ],
                "primaryGroupID": [513],
                "userAccountControl": [512],
                "badPwdCount": [0],
                "adminCount": [1],
                "servicePrincipalName": [],
                "cn": ["John Doe"],
            },
        }
        users = self.enumerator._parse_users([entry])
        assert len(users) == 1
        u = users[0]
        assert u.sam_account_name == "jdoe"
        assert u.user_principal_name == "jdoe@corp.local"
        assert u.mail == "john@corp.local"
        assert u.title == "Manager"
        assert u.is_admin is True
        assert u.is_enabled is True
        assert len(u.member_of) == 2

    def test_parse_user_kerberoastable(self):
        entry = {
            "dn": "CN=SvcAccount,CN=Users,DC=corp,DC=local",
            "attributes": {
                "sAMAccountName": ["svc_web"],
                "userPrincipalName": ["svc_web@corp.local"],
                "displayName": ["Svc Account"],
                "servicePrincipalName": [
                    "HTTP/web.corp.local",
                    "HTTP/web.internal.corp.local",
                ],
                "memberOf": [],
                "primaryGroupID": [513],
                "userAccountControl": [512],
                "adminCount": [0],
                "cn": ["SvcAccount"],
            },
        }
        users = self.enumerator._parse_users([entry])
        assert len(users[0].service_principal_names) == 2
        assert users[0].is_kerberoastable is True

    def test_parse_group(self):
        entry = {
            "dn": "CN=Domain Admins,CN=Users,DC=corp,DC=local",
            "attributes": {
                "sAMAccountName": ["Domain Admins"],
                "cn": ["Domain Admins"],
                "groupType": [-2147483646],
                "member": [
                    "CN=Administrator,CN=Users,DC=corp,DC=local",
                ],
                "memberOf": [],
                "adminCount": [1],
            },
        }
        groups = self.enumerator._parse_groups([entry])
        assert len(groups) == 1
        g = groups[0]
        assert g.sam_account_name == "Domain Admins"
        assert g.is_security_group is True
        assert g.admin_count == 1
        assert len(g.members) == 1

    def test_parse_computer_dc(self):
        entry = {
            "dn": "CN=DC01,OU=Domain Controllers,DC=corp,DC=local",
            "attributes": {
                "sAMAccountName": ["DC01$"],
                "dNSHostName": ["dc01.corp.local"],
                "operatingSystem": ["Windows Server 2019"],
                "operatingSystemVersion": ["10.0 (17763)"],
                "memberOf": [],
                "userAccountControl": [532480],  # SERVER_TRUST + TRUSTED_FOR_DELEG
                "servicePrincipalName": [],
                "cn": ["DC01"],
            },
        }
        computers = self.enumerator._parse_computers([entry])
        assert len(computers) == 1
        c = computers[0]
        assert c.dns_hostname == "dc01.corp.local"
        assert c.is_domain_controller is True

    def test_parse_ou(self):
        entry = {
            "dn": "OU=IT,DC=corp,DC=local",
            "attributes": {
                "ou": ["IT"],
                "cn": ["IT"],
                "gPLink": [
                    "[LDAP://cn={GUID1},cn=policies,cn=system,DC=corp,DC=local;0]"
                    "[LDAP://cn={GUID2},cn=policies,cn=system,DC=corp,DC=local;1]"
                ],
            },
        }
        ous = self.enumerator._parse_ous([entry])
        assert len(ous) == 1
        assert ous[0].ou_name == "IT"
        assert len(ous[0].gpo_links) == 2

    def test_parse_gpo(self):
        entry = {
            "dn": "CN={GUID},CN=Policies,CN=System,DC=corp,DC=local",
            "attributes": {
                "displayName": ["Default Domain Policy"],
                "cn": ["{GUID}"],
                "gPCFileSysPath": [
                    "\\\\corp.local\\SysVol\\corp.local\\Policies\\{GUID}"
                ],
                "versionNumber": [65536],
                "flags": [0],
            },
        }
        gpos = self.enumerator._parse_gpos([entry])
        assert len(gpos) == 1
        assert gpos[0].display_name == "Default Domain Policy"
        assert gpos[0].gpo_status == "Enabled"

    def test_parse_trust(self):
        entry = {
            "dn": "CN=child.corp.local,CN=System,DC=corp,DC=local",
            "attributes": {
                "trustPartner": ["child.corp.local"],
                "trustDirection": ["3"],  # Bidirectional
                "trustType": ["2"],       # Uplevel (AD)
                "trustAttributes": [32],  # WITHIN_FOREST
            },
        }
        trusts = self.enumerator._parse_trusts([entry], "corp.local")
        assert len(trusts) == 1
        t = trusts[0]
        assert t.source_domain == "corp.local"
        assert t.target_domain == "child.corp.local"
        assert t.direction == "Bidirectional"
        assert t.type == "Uplevel (AD)"
        assert t.sid_filtering is False  # WITHIN_FOREST → pas de SID filtering

    def test_parse_malformed_entry(self):
        """Les entrées malformées ne doivent pas casser le parsing."""
        entry = {"dn": "CN=BadEntry", "attributes": {}}
        users = self.enumerator._parse_users([entry])
        assert len(users) == 1
        assert users[0].sam_account_name == ""


# ═══════════════════════════════════════════════════════════════
# DomainMap
# ═══════════════════════════════════════════════════════════════

class TestDomainMap:
    def _build_domain_map(self) -> DomainMap:
        """Construit une DomainMap minimale mais réaliste."""
        domain = ADDomain(
            name="corp.local",
            netbios_name="CORP",
            sid="S-1-5-21-123456789-123456789-123456789",
            functional_level="2016",
            forest="corp.local",
            dc_hostnames=["dc01.corp.local"],
        )

        # Utilisateurs
        admin = ADUser(
            dn="CN=Administrator,CN=Users,DC=corp,DC=local",
            sam_account_name="Administrator",
            user_principal_name="admin@corp.local",
            display_name="Administrator",
            admin_count=1,
            user_account_control=0x10000 | 512,  # DONT_EXPIRE_PASSWORD
            member_of=["CN=Domain Admins,CN=Users,DC=corp,DC=local"],
        )
        svc = ADUser(
            dn="CN=SvcWeb,CN=Users,DC=corp,DC=local",
            sam_account_name="svc_web",
            display_name="Web Service",
            service_principal_names=["HTTP/web.corp.local"],
            member_of=["CN=Domain Admins,CN=Users,DC=corp,DC=local"],
        )
        user = ADUser(
            dn="CN=John,CN=Users,DC=corp,DC=local",
            sam_account_name="jdoe",
            display_name="John Doe",
            user_account_control=514,  # Disabled
        )
        asrep_user = ADUser(
            dn="CN=Legacy,CN=Users,DC=corp,DC=local",
            sam_account_name="legacy",
            user_account_control=0x400000,  # DONT_REQ_PREAUTH
        )

        # Groupes
        domain_admins = ADGroup(
            dn="CN=Domain Admins,CN=Users,DC=corp,DC=local",
            sam_account_name="Domain Admins",
            members=[
                "CN=Administrator,CN=Users,DC=corp,DC=local",
                "CN=SvcWeb,CN=Users,DC=corp,DC=local",
            ],
            admin_count=1,
        )

        # Ordinateurs
        dc01 = ADComputer(
            dn="CN=DC01,OU=Domain Controllers,DC=corp,DC=local",
            sam_account_name="DC01$",
            dns_hostname="dc01.corp.local",
            user_account_control=0x2000,  # SERVER_TRUST
        )
        ws01 = ADComputer(
            dn="CN=WS01,CN=Computers,DC=corp,DC=local",
            sam_account_name="WS01$",
            dns_hostname="ws01.corp.local",
            user_account_control=0x80000,  # TRUSTED_FOR_DELEGATION
        )

        # Trusts
        trust = ADTrust(
            source_domain="corp.local",
            target_domain="child.corp.local",
            direction="Bidirectional",
            type="Uplevel (AD)",
            transitive=True,
        )

        return DomainMap(
            domain=domain,
            users=[admin, svc, user, asrep_user],
            groups=[domain_admins],
            computers=[dc01, ws01],
            ous=[],
            gpos=[],
            trusts=[trust],
            _users_by_dn={
                admin.dn: admin, svc.dn: svc,
                user.dn: user, asrep_user.dn: asrep_user,
            },
            _groups_by_dn={domain_admins.dn: domain_admins},
            _computers_by_dn={dc01.dn: dc01, ws01.dn: ws01},
            _groups_by_sam={"Domain Admins": domain_admins},
        )

    def test_total_objects(self):
        dm = self._build_domain_map()
        assert dm.total_objects == 8  # 4 users + 1 group + 2 computers + 1 trust

    def test_privileged_users(self):
        dm = self._build_domain_map()
        assert len(dm.privileged_users) == 1
        assert dm.privileged_users[0].sam_account_name == "Administrator"

    def test_kerberoastable_users(self):
        dm = self._build_domain_map()
        assert len(dm.kerberoastable_users) == 1
        assert dm.kerberoastable_users[0].sam_account_name == "svc_web"

    def test_asrep_roastable_users(self):
        dm = self._build_domain_map()
        assert len(dm.asrep_roastable_users) == 1
        assert dm.asrep_roastable_users[0].sam_account_name == "legacy"

    def test_domain_admins(self):
        dm = self._build_domain_map()
        admins = dm.domain_admins
        admin_names = {a.sam_account_name for a in admins}
        assert "Administrator" in admin_names
        assert "svc_web" in admin_names
        assert len(admins) == 2

    def test_domain_controllers(self):
        dm = self._build_domain_map()
        assert len(dm.domain_controllers) == 1
        assert dm.domain_controllers[0].dns_hostname == "dc01.corp.local"

    def test_unconstrained_delegation(self):
        dm = self._build_domain_map()
        assert len(dm.unconstrained_delegation_computers) == 1
        assert dm.unconstrained_delegation_computers[0].dns_hostname == "ws01.corp.local"

    def test_disabled_users(self):
        dm = self._build_domain_map()
        assert len(dm.disabled_users) == 1
        assert dm.disabled_users[0].sam_account_name == "jdoe"

    def test_summary(self):
        dm = self._build_domain_map()
        summary = dm.summary()
        assert "corp.local" in summary
        assert "CORP" in summary
        assert "Users: 4" in summary
        assert "Groups: 1" in summary
        assert "Computers: 2" in summary


# ═══════════════════════════════════════════════════════════════
# EnumerationResult
# ═══════════════════════════════════════════════════════════════

class TestEnumerationResult:
    def test_success_no_errors(self):
        result = EnumerationResult(
            domain="test.local",
            domain_map=DomainMap(domain=ADDomain(name="test.local")),
        )
        assert result.success is True

    def test_success_with_errors(self):
        result = EnumerationResult(
            domain="test.local",
            domain_map=DomainMap(domain=ADDomain(name="test.local")),
            errors=["Connection refused"],
        )
        assert result.success is False


# ═══════════════════════════════════════════════════════════════
# Mappings & Constants
# ═══════════════════════════════════════════════════════════════

class TestMappings:
    def test_functional_level_map(self):
        assert FUNCTIONAL_LEVEL_MAP["7"] == "2016"
        assert FUNCTIONAL_LEVEL_MAP["10"] == "2025"

    def test_trust_direction_map(self):
        assert TRUST_DIRECTION_MAP["3"] == "Bidirectional"
        assert TRUST_DIRECTION_MAP["1"] == "Inbound"

    def test_trust_type_map(self):
        assert TRUST_TYPE_MAP["2"] == "Uplevel (AD)"
        assert TRUST_TYPE_MAP["1"] == "Downlevel (NT4)"


# ═══════════════════════════════════════════════════════════════
# ADTrustGraph
# ═══════════════════════════════════════════════════════════════

class TestADTrustGraph:
    """Tests du graphe d'attaque AD (BloodHound-like)."""

    def _build_graph(self):
        """Construit un graphe à partir d'une DomainMap réaliste."""
        from navmax.ad.trust_graph import ADTrustGraph
        dm = TestDomainMap()._build_domain_map()
        graph = ADTrustGraph()
        graph.build(dm)
        return graph

    def test_build_creates_nodes(self):
        graph = self._build_graph()
        assert graph.node_count > 0
        # 1 domain + 4 users + 1 group + 2 computers + 1 trust domain = 9
        assert graph.node_count == 9

    def test_build_creates_edges(self):
        graph = self._build_graph()
        assert graph.edge_count > 0
        # MemberOf: admin→DA, svc_web→DA = 2
        # AdminTo: admin→DC01, svc_web→DC01 = 2
        # TrustedBy: child→corp = 1
        # HasSPN: svc_web→svc_web = 1
        # ASREPRoastable: legacy→legacy = 1
        # TrustedForDelegation: ws01→ws01 = 1
        assert graph.edge_count >= 6

    def test_find_shortest_path_to_da_admin(self):
        graph = self._build_graph()
        path = graph.find_shortest_path_to_da("Administrator")
        assert path is not None
        assert path.length == 1  # Administrator → Domain Admins
        assert path.path_labels[-1] == "Domain Admins"

    def test_find_shortest_path_to_da_svc(self):
        graph = self._build_graph()
        path = graph.find_shortest_path_to_da("svc_web")
        assert path is not None
        assert path.length == 1  # svc_web → Domain Admins

    def test_find_shortest_path_to_da_unprivileged(self):
        graph = self._build_graph()
        path = graph.find_shortest_path_to_da("jdoe")
        # jdoe n'est pas dans Domain Admins → pas de chemin
        assert path is None

    def test_get_effective_domain_admins(self):
        graph = self._build_graph()
        admins = graph.get_effective_domain_admins()
        assert "Administrator" in admins
        assert "svc_web" in admins
        assert len(admins) == 2

    def test_find_kerberoastable_paths(self):
        graph = self._build_graph()
        paths = graph.find_kerberoastable_paths()
        # svc_web a un SPN et est dans DA
        assert len(paths) >= 1
        assert paths[0].path_labels[0] == "svc_web"

    def test_find_asrep_roastable_targets(self):
        graph = self._build_graph()
        targets = graph.find_asrep_roastable_targets()
        assert "legacy" in targets

    def test_find_unconstrained_delegation_hosts(self):
        graph = self._build_graph()
        hosts = graph.find_unconstrained_delegation_hosts()
        assert "ws01.corp.local" in hosts

    def test_get_high_value_targets(self):
        graph = self._build_graph()
        hv = graph.get_high_value_targets()
        hv_names = [n.name for n in hv]
        # Domain, Domain Admins group, Administrator, DC01
        assert any("corp.local" in n or n == "corp.local" for n in hv_names)
        assert "Domain Admins" in hv_names or any(
            "Domain Admins" in n for n in hv_names
        )
        assert "Administrator" in hv_names
        assert "dc01.corp.local" in hv_names

    def test_get_user_effective_groups(self):
        graph = self._build_graph()
        groups = graph.get_user_effective_groups("Administrator")
        assert "Domain Admins" in groups

    def test_export_bloodhound_json(self):
        graph = self._build_graph()
        data = graph.export_bloodhound_json()
        assert "nodes" in data
        assert "edges" in data
        assert "metadata" in data
        assert data["metadata"]["domain"] == "corp.local"
        assert len(data["nodes"]) == graph.node_count
        assert len(data["edges"]) == graph.edge_count

    def test_summary(self):
        graph = self._build_graph()
        summary = graph.summary()
        assert "corp.local" in summary
        assert "Nodes:" in summary

    def test_find_most_exposed_users(self):
        graph = self._build_graph()
        exposed = graph.find_most_exposed_users(top_n=5)
        # Tous les utilisateurs actifs apparaissent ; au moins 2 ont des chemins valides
        assert len(exposed) >= 3  # legacy, Administrator, svc_web (jdoe est disabled)
        exposed_valid = [e for e in exposed if e["shortest_path_length"] >= 0]
        assert len(exposed_valid) >= 2
        exposed_names = [e["user"] for e in exposed_valid]
        assert "Administrator" in exposed_names
        assert "svc_web" in exposed_names

    def test_find_all_paths_to_da(self):
        graph = self._build_graph()
        paths = graph.find_all_paths_to_da("Administrator")
        assert len(paths) >= 1
        assert paths[0].length == 1

    def test_empty_graph(self):
        from navmax.ad.trust_graph import ADTrustGraph
        graph = ADTrustGraph()
        assert graph.node_count == 0
        assert graph.edge_count == 0

    def test_node_types(self):
        graph = self._build_graph()
        from navmax.ad.trust_graph import NodeType
        types = set()
        for node_id in graph.graph.nodes():
            node_data = graph.graph.nodes[node_id]
            types.add(node_data.get("type"))
        assert NodeType.USER in types
        assert NodeType.GROUP in types
        assert NodeType.COMPUTER in types
        assert NodeType.DOMAIN in types


# ═══════════════════════════════════════════════════════════════
# AttackPathAnalyzer (sans IA — mode dégradé algorithmique)
# ═══════════════════════════════════════════════════════════════

class TestAttackPathAnalyzer:
    """Tests de l'analyseur de chemins d'attaque (fallback sans IA)."""

    def _get_graph(self):
        from navmax.ad.trust_graph import ADTrustGraph
        dm = TestDomainMap()._build_domain_map()
        graph = ADTrustGraph()
        graph.build(dm)
        return graph

    @pytest.mark.asyncio
    async def test_fallback_analysis(self):
        from navmax.ad.attack_paths import AttackPathAnalyzer
        graph = self._get_graph()
        analyzer = AttackPathAnalyzer(ai_engine=None)
        analysis = await analyzer.analyze(graph)

        assert analysis.overall_risk_level in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        assert analysis.exposed_users_count >= 0
        assert analysis.kerberoastable_accounts_leading_to_da >= 0
        assert len(analysis.executive_summary) > 10

    @pytest.mark.asyncio
    async def test_fallback_report_not_empty(self):
        from navmax.ad.attack_paths import AttackPathAnalyzer
        graph = self._get_graph()
        analyzer = AttackPathAnalyzer(ai_engine=None)
        analysis = await analyzer.analyze(graph)

        report = analysis.report
        assert "NAVMAX" in report
        assert "RISK" in report

    @pytest.mark.asyncio
    async def test_fallback_has_critical_paths(self):
        from navmax.ad.attack_paths import AttackPathAnalyzer
        graph = self._get_graph()
        analyzer = AttackPathAnalyzer(ai_engine=None)
        analysis = await analyzer.analyze(graph)

        # Doit trouver au moins le chemin Kerberoasting
        assert len(analysis.critical_paths) >= 1

    @pytest.mark.asyncio
    async def test_fallback_has_risks(self):
        from navmax.ad.attack_paths import AttackPathAnalyzer
        graph = self._get_graph()
        analyzer = AttackPathAnalyzer(ai_engine=None)
        analysis = await analyzer.analyze(graph)

        assert len(analysis.top_risks) >= 1
        for risk in analysis.top_risks:
            assert risk.finding
            assert risk.severity in ("critical", "high", "medium", "low")

    @pytest.mark.asyncio
    async def test_attack_path_analysis_dataclass(self):
        from navmax.ad.attack_paths import (
            AttackPathAnalysis, CriticalPath, RiskFinding,
        )
        cp = CriticalPath(
            name="Test Path",
            source="user",
            target="DA",
            steps=["user → group → DA"],
            technique="Kerberoasting",
            risk_score=85.0,
            business_impact="Full compromise",
            remediation="Remove SPN",
        )
        risk = RiskFinding(
            finding="Test finding",
            severity="critical",
            affected_assets=5,
        )
        analysis = AttackPathAnalysis(
            critical_paths=[cp],
            top_risks=[risk],
            exposed_users_count=12,
            kerberoastable_accounts_leading_to_da=3,
            overall_risk_level="CRITICAL",
            executive_summary="Test summary",
        )

        assert analysis.overall_risk_level == "CRITICAL"
        report = analysis.report
        assert "Test Path" in report
        assert "CRITICAL" in report
        assert "Test finding" in report

    @pytest.mark.asyncio
    async def test_quick_analysis(self):
        from navmax.ad.attack_paths import quick_analysis
        graph = self._get_graph()
        analysis = await quick_analysis(graph, ai_engine=None)
        assert analysis.overall_risk_level in ("CRITICAL", "HIGH", "MEDIUM", "LOW")


# ═══════════════════════════════════════════════════════════════
# ADVulnScanner
# ═══════════════════════════════════════════════════════════════

class TestADVulnScanner:
    """Tests du scanner de vulnérabilités AD."""

    def _get_domain_map(self):
        return TestDomainMap()._build_domain_map()

    @pytest.mark.asyncio
    async def test_scan_all_finds_kerberoasting(self):
        from navmax.ad.vuln_scanner import ADVulnScanner
        dm = self._get_domain_map()
        scanner = ADVulnScanner()
        report = await scanner.scan_all(dm)

        # Doit trouver le compte kerberoastable (svc_web)
        kerb_findings = [
            f for f in report.findings
            if f.category == "kerberoasting"
        ]
        assert len(kerb_findings) >= 1

    @pytest.mark.asyncio
    async def test_scan_all_finds_asrep_roasting(self):
        from navmax.ad.vuln_scanner import ADVulnScanner
        dm = self._get_domain_map()
        scanner = ADVulnScanner()
        report = await scanner.scan_all(dm)

        asrep_findings = [
            f for f in report.findings
            if f.category == "asrep_roasting"
        ]
        assert len(asrep_findings) >= 1

    @pytest.mark.asyncio
    async def test_scan_all_finds_delegation(self):
        from navmax.ad.vuln_scanner import ADVulnScanner
        dm = self._get_domain_map()
        scanner = ADVulnScanner()
        report = await scanner.scan_all(dm)

        del_findings = [
            f for f in report.findings
            if f.category == "delegation"
        ]
        # ws01 a la délégation non contrainte
        assert len(del_findings) >= 1

    @pytest.mark.asyncio
    async def test_scan_all_finds_privileged(self):
        from navmax.ad.vuln_scanner import ADVulnScanner
        dm = self._get_domain_map()
        scanner = ADVulnScanner()
        report = await scanner.scan_all(dm)

        priv_findings = [
            f for f in report.findings
            if f.category == "privileged_accounts"
        ]
        assert len(priv_findings) >= 1

    @pytest.mark.asyncio
    async def test_report_has_summary(self):
        from navmax.ad.vuln_scanner import ADVulnScanner
        dm = self._get_domain_map()
        scanner = ADVulnScanner()
        report = await scanner.scan_all(dm)

        summary = report.summary()
        assert "corp.local" in summary
        assert "Total findings" in summary

    @pytest.mark.asyncio
    async def test_report_detailed(self):
        from navmax.ad.vuln_scanner import ADVulnScanner
        dm = self._get_domain_map()
        scanner = ADVulnScanner()
        report = await scanner.scan_all(dm)

        detailed = report.detailed_report()
        assert "CRITICAL" in detailed or "HIGH" in detailed or "MEDIUM" in detailed

    @pytest.mark.asyncio
    async def test_quick_vuln_scan(self):
        from navmax.ad.vuln_scanner import quick_vuln_scan
        dm = self._get_domain_map()
        report = await quick_vuln_scan(dm)
        assert report.total_findings >= 0

    def test_vuln_finding_str(self):
        from navmax.ad.vuln_scanner import (
            VulnFinding, FindingSeverity, FindingCategory,
        )
        f = VulnFinding(
            title="Test",
            description="Desc",
            severity=FindingSeverity.CRITICAL,
            category=FindingCategory.KERBEROASTING,
            affected_assets=["user1"],
            affected_count=1,
        )
        s = str(f)
        assert "CRITICAL" in s
        assert "Test" in s

    def test_report_by_severity(self):
        from navmax.ad.vuln_scanner import (
            ScanReport, VulnFinding, FindingSeverity, FindingCategory,
        )
        report = ScanReport(domain="test.local")
        report.findings.append(VulnFinding(
            title="C", severity=FindingSeverity.CRITICAL,
            category=FindingCategory.KERBEROASTING, affected_count=1,
            description="", remediation="",
        ))
        report.findings.append(VulnFinding(
            title="H", severity=FindingSeverity.HIGH,
            category=FindingCategory.DELEGATION, affected_count=1,
            description="", remediation="",
        ))
        assert report.critical_count == 1
        assert report.high_count == 1
        assert len(report.by_severity(FindingSeverity.CRITICAL)) == 1


# ═══════════════════════════════════════════════════════════════
# PasswordSprayer (sans connexion réelle)
# ═══════════════════════════════════════════════════════════════

class TestPasswordSprayer:
    """Tests du pulvérisateur de mots de passe."""

    def test_default_wordlist_not_empty(self):
        from navmax.ad.password_spray import get_full_default_wordlist
        wl = get_full_default_wordlist()
        assert len(wl) > 10

    def test_seasonal_wordlist(self):
        from navmax.ad.password_spray import get_seasonal_wordlist
        wl = get_seasonal_wordlist()
        assert isinstance(wl, list)

    def test_spray_config_defaults(self):
        from navmax.ad.password_spray import SprayConfig, SprayMode
        config = SprayConfig()
        assert config.mode == SprayMode.SAFE
        assert config.effective_delay == 1800.0
        assert config.avoid_disabled is True
        assert config.dry_run is False

    def test_spray_config_modes(self):
        from navmax.ad.password_spray import SprayConfig, SprayMode
        assert SprayConfig(mode=SprayMode.SAFE).effective_delay == 1800.0
        assert SprayConfig(mode=SprayMode.NORMAL).effective_delay == 300.0
        assert SprayConfig(mode=SprayMode.AGGRESSIVE).effective_delay == 30.0
        assert SprayConfig(
            mode=SprayMode.CUSTOM, delay_seconds=60.0
        ).effective_delay == 60.0

    def test_spray_result(self):
        from navmax.ad.password_spray import SprayResult
        r = SprayResult(username="user", password="pass", success=True)
        assert r.success is True
        assert r.username == "user"

    def test_spray_session_summary(self):
        from navmax.ad.password_spray import (
            SpraySession, SprayConfig, SprayResult,
        )
        session = SpraySession(
            config=SprayConfig(),
            total_users=10,
            total_passwords=3,
            total_attempts=30,
            successes=[SprayResult(username="u1", password="p1", success=True)],
            failures=29,
        )
        summary = session.summary()
        assert "u1" in summary
        assert "p1" in summary
        assert "Successes: 1" in summary

    def test_wordlist_deduplication(self):
        from navmax.ad.password_spray import PasswordSprayer
        sprayer = PasswordSprayer()
        sprayer.set_wordlist(["Password1", "Password1", "Password2"])
        assert len(sprayer._wordlist) == 2  # pas de doublons

    def test_wordlist_from_file(self, tmp_path):
        from navmax.ad.password_spray import PasswordSprayer
        wordlist_file = tmp_path / "passwords.txt"
        wordlist_file.write_text("Password1\n# comment\nSummer2026\n\n")
        sprayer = PasswordSprayer()
        count = sprayer.load_wordlist_file(str(wordlist_file))
        assert count == 2
        assert "Password1" in sprayer._wordlist

    def test_prepare_user_list_filters_disabled(self):
        from navmax.ad.password_spray import PasswordSprayer, SprayConfig
        from navmax.ad.connector import ADUser
        sprayer = PasswordSprayer(config=SprayConfig(avoid_disabled=True))
        users = [
            ADUser(dn="CN=A", sam_account_name="active",
                   user_account_control=512),
            ADUser(dn="CN=B", sam_account_name="disabled",
                   user_account_control=514),  # ACCOUNTDISABLE
        ]
        result = sprayer._prepare_user_list(users)
        assert len(result) == 1
        assert result[0]["username"] == "active"

    def test_prepare_user_list_respects_target_list(self):
        from navmax.ad.password_spray import PasswordSprayer, SprayConfig
        from navmax.ad.connector import ADUser
        sprayer = PasswordSprayer(config=SprayConfig(
            target_users=["admin", "svc"],
        ))
        users = [
            ADUser(dn="CN=A", sam_account_name="admin",
                   user_account_control=512),
            ADUser(dn="CN=B", sam_account_name="user1",
                   user_account_control=512),
            ADUser(dn="CN=C", sam_account_name="svc",
                   user_account_control=512),
        ]
        result = sprayer._prepare_user_list(users)
        assert len(result) == 2
        names = [r["username"] for r in result]
        assert "admin" in names
        assert "svc" in names

    @pytest.mark.asyncio
    async def test_spray_without_connector_raises(self):
        from navmax.ad.password_spray import PasswordSprayer
        sprayer = PasswordSprayer(connector=None)
        sprayer.set_wordlist(["test"])
        with pytest.raises(ValueError, match="requires an active"):
            await sprayer.spray_user_list([])


# ═══════════════════════════════════════════════════════════════
# SMB Scanner (sans connexion réelle)
# ═══════════════════════════════════════════════════════════════

class TestSMSScanner:
    """Tests du scanner SMB."""

    def _get_domain_map(self):
        return TestDomainMap()._build_domain_map()

    def test_smb_share_defaults(self):
        from navmax.ad.smb_scanner import SMBShare
        s = SMBShare(name="C$", path="C:\\", is_admin_share=True)
        assert s.is_admin_share is True
        assert s.is_writable is False

    def test_smb_computer_result_defaults(self):
        from navmax.ad.smb_scanner import SMBComputerResult
        r = SMBComputerResult(hostname="test")
        assert r.risky is False
        assert r.has_writable_shares is False

    def test_smb_domain_report(self):
        from navmax.ad.smb_scanner import SMBDomainReport
        report = SMBDomainReport(domain="test.local")
        assert len(report.smbv1_hosts) == 0
        assert len(report.relay_vulnerable_hosts) == 0

    @pytest.mark.asyncio
    async def test_scan_domain_no_connector(self):
        from navmax.ad.smb_scanner import ADSMSScanner
        dm = self._get_domain_map()
        scanner = ADSMSScanner(timeout=2.0)
        report = await scanner.scan_domain(dm)
        assert report.domain == "corp.local"
        assert report.computers_scanned >= 0

    @pytest.mark.asyncio
    async def test_scan_computer_unreachable(self):
        from navmax.ad.smb_scanner import ADSMSScanner
        scanner = ADSMSScanner(timeout=2.0)
        # Hostname qui n'existe pas → résultat avec error
        result = await scanner.scan_computer("192.0.2.1")  # TEST-NET-1
        assert isinstance(result.hostname, str)

    def test_probe_smb_unreachable(self):
        from navmax.ad.smb_scanner import ADSMSScanner
        import asyncio
        scanner = ADSMSScanner(timeout=2.0)
        info = asyncio.run(scanner._probe_smb("192.0.2.1"))
        assert "hostname" in info

    def test_smb_report_summary(self):
        from navmax.ad.smb_scanner import (
            SMBDomainReport, SMBComputerResult, SMBShare,
        )
        report = SMBDomainReport(domain="test.local")
        result = SMBComputerResult(hostname="dc01", smbv1_enabled=True,
                                    writable_shares=1)
        result.shares = [
            SMBShare(name="public", is_writable=True),
        ]
        report.results.append(result)
        summary = report.summary()
        assert "dc01" in summary
        assert "public" in summary


# ═══════════════════════════════════════════════════════════════
# ADCS Scanner (sans connexion réelle)
# ═══════════════════════════════════════════════════════════════

class TestADCSSCanner:
    """Tests du scanner ADCS."""

    def _get_domain_map(self):
        return TestDomainMap()._build_domain_map()

    def test_template_info_defaults(self):
        from navmax.ad.adcs_scanner import TemplateInfo
        t = TemplateInfo(name="User", dn="CN=User,...")
        assert t.enrollee_supplies_subject is False
        assert t.has_client_auth_eku is False

    def test_ca_info_defaults(self):
        from navmax.ad.adcs_scanner import CAInfo
        ca = CAInfo(name="CA1", dn="CN=CA1,...")
        assert ca.editf_attributesubjectaltname2 is False
        assert ca.web_enrollment_enabled is False

    @pytest.mark.asyncio
    async def test_scan_without_connector(self):
        from navmax.ad.adcs_scanner import ADCSSCanner
        dm = self._get_domain_map()
        scanner = ADCSSCanner(connector=None)
        report = await scanner.scan_all(dm)
        assert len(report.errors) >= 1  # No active connector
        assert len(report.cas) == 0

    def test_adcs_finding(self):
        from navmax.ad.adcs_scanner import ADCSFinding, ESCSeverity
        f = ADCSFinding(
            esc_id="ESC1",
            title="Test",
            description="Desc",
            severity=ESCSeverity.CRITICAL,
            affected_templates=["Template1"],
        )
        assert f.esc_id == "ESC1"
        assert f.severity == "critical"

    def test_report_summary_empty(self):
        from navmax.ad.adcs_scanner import ADCSReport
        report = ADCSReport(domain="test.local")
        summary = report.summary()
        assert "test.local" in summary
        assert "0" in summary

    def test_check_esc1_detection_logic(self):
        from navmax.ad.adcs_scanner import (
            ADCSSCanner, ADCSReport, TemplateInfo,
        )
        scanner = ADCSSCanner()
        report = ADCSReport(domain="test.local")
        report.templates = [
            TemplateInfo(
                name="VulnTemplate",
                dn="CN=Vuln,...",
                enrollee_supplies_subject=True,
                has_client_auth_eku=True,
                requires_manager_approval=False,
                ekus=["1.3.6.1.5.5.7.3.2"],
            ),
            TemplateInfo(
                name="SafeTemplate",
                dn="CN=Safe,...",
                enrollee_supplies_subject=False,
                has_client_auth_eku=True,
            ),
        ]
        scanner._check_esc1(report)
        assert len(report.findings) >= 1
        assert report.findings[0].esc_id == "ESC1"

    def test_check_esc6_detection_logic(self):
        from navmax.ad.adcs_scanner import (
            ADCSSCanner, ADCSReport, CAInfo,
        )
        scanner = ADCSSCanner()
        report = ADCSReport(domain="test.local")
        report.cas = [
            CAInfo(
                name="VulnCA",
                dn="CN=VulnCA,...",
                editf_attributesubjectaltname2=True,
            ),
        ]
        scanner._check_esc6(report)
        assert len(report.findings) >= 1
        assert report.findings[0].esc_id == "ESC6"

    def test_check_esc2_detection_logic(self):
        from navmax.ad.adcs_scanner import (
            ADCSSCanner, ADCSReport, TemplateInfo,
        )
        scanner = ADCSSCanner()
        report = ADCSReport(domain="test.local")
        report.templates = [
            TemplateInfo(
                name="AnyPurpose",
                dn="CN=Any,...",
                has_any_purpose_eku=True,
                ekus=["2.5.29.37.0"],
            ),
        ]
        scanner._check_esc2(report)
        assert len(report.findings) >= 1
        assert report.findings[0].esc_id == "ESC2"
