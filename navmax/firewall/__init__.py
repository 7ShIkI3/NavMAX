"""
Module Firewall — connecteurs API pour équipements réseau.

Fonctionnalités :
- Connecteurs FortiGate (REST API) avec vérification CVE
- Connecteurs StormShield SNS (CONF API)
- Analyse intelligente des règles (shadowing, Any/Any, ports à risque)
- Corrélation AD × règles firewall (vue unifiée infrastructure)
"""

from .base import (
    FirewallConnector, FirewallVendor, FirewallConfig,
    FirewallRule, FirewallInterface, FirewallAddress, FirewallUser,
    CVECheck, RuleAction, Protocol, RuleSeverity,
)
from .fortigate import FortiGateConnector
from .stormshield import StormShieldConnector
from .rule_analyzer import RuleAnalyzer, RuleFinding, RuleAnalysisReport, FindingType
from .correlation import ADCorrelator, CorrelationFinding, CorrelationReport, CorrelationSeverity

__all__ = [
    # Base
    "FirewallConnector", "FirewallVendor", "FirewallConfig",
    "FirewallRule", "FirewallInterface", "FirewallAddress", "FirewallUser",
    "CVECheck", "RuleAction", "Protocol", "RuleSeverity",
    # Connectors
    "FortiGateConnector",
    "StormShieldConnector",
    # Analysis
    "RuleAnalyzer", "RuleFinding", "RuleAnalysisReport", "FindingType",
    # Correlation
    "ADCorrelator", "CorrelationFinding", "CorrelationReport", "CorrelationSeverity",
]
