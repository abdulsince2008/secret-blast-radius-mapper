"""Dependency graph builder for blast radius analysis."""
import networkx as nx
from typing import List, Dict, Set, Optional
from src.models import (
    SecretFinding, ConfigReference, ServiceNode, BlastRadiusResult, SecretType
)


def build_service_graph(config_refs: List[ConfigReference]) -> Dict[str, ServiceNode]:
    """Build a map of services from config references."""
    services: Dict[str, ServiceNode] = {}
    
    for ref in config_refs:
        service_name = ref.service_name or "unknown"
        
        if service_name not in services:
            # Determine service type from config type
            service_type = infer_service_type(ref.config_type, ref.config_file)
            services[service_name] = ServiceNode(
                name=service_name,
                type=service_type,
            )
        
        service = services[service_name]
        if ref.config_file not in service.config_files:
            service.config_files.append(ref.config_file)
        if ref.variable_name not in service.environment_variables:
            service.environment_variables.append(ref.variable_name)
    
    return services


def infer_service_type(config_type: str, config_file: str) -> str:
    """Infer service type from config type and file path."""
    if config_type == "docker-compose":
        return "container"
    elif config_type == "kubernetes":
        return "k8s-workload"
    elif config_type == "github-actions":
        return "ci-cd"
    elif config_type == "env":
        return "application"
    return "unknown"


def infer_dependencies(services: Dict[str, ServiceNode], config_refs: List[ConfigReference]) -> None:
    """Infer service dependencies from shared secrets and config."""
    # Build secret -> services mapping
    secret_to_services: Dict[str, Set[str]] = {}
    
    for ref in config_refs:
        service_name = ref.service_name or "unknown"
        # Use variable name as a proxy for shared secret
        secret_key = ref.variable_name.lower()
        if secret_key not in secret_to_services:
            secret_to_services[secret_key] = set()
        secret_to_services[secret_key].add(service_name)
    
    # Services sharing the same secret variable are likely connected
    for secret, svc_set in secret_to_services.items():
        if len(svc_set) > 1:
            for svc in svc_set:
                for other in svc_set:
                    if svc != other and other not in services[svc].depends_on:
                        services[svc].depends_on.append(other)


def calculate_blast_radius(
    secret: SecretFinding,
    config_refs: List[ConfigReference],
    services: Dict[str, ServiceNode]
) -> BlastRadiusResult:
    """Calculate blast radius for a secret finding."""
    
    # Find config references that might be related to this secret
    related_refs = []
    secret_keywords = extract_secret_keywords(secret)
    
    for ref in config_refs:
        if is_related(ref, secret_keywords):
            related_refs.append(ref)
    
    # Find affected services
    affected_service_names = set()
    for ref in related_refs:
        if ref.service_name:
            affected_service_names.add(ref.service_name)
    
    affected_services = [services[name] for name in affected_service_names if name in services]
    
    # Calculate blast radius score (0-100)
    score = calculate_risk_score(secret, related_refs, affected_services)
    risk_level = score_to_risk_level(score)
    
    return BlastRadiusResult(
        secret=secret,
        origin_commit=None,  # Will be filled by git tracer
        introduced_by=None,
        introduced_date=None,
        config_references=related_refs,
        affected_services=affected_services,
        blast_radius_score=score,
        risk_level=risk_level,
    )


def extract_secret_keywords(secret: SecretFinding) -> List[str]:
    """Extract keywords from secret for matching."""
    keywords = [secret.secret_type.value.lower()]
    
    # Add parts of the rule ID
    rule_parts = secret.rule_id.lower().replace('-', ' ').split()
    keywords.extend(rule_parts)
    
    # Add common prefixes/suffixes
    if secret.secret_type == SecretType.AWS_ACCESS_KEY:
        keywords.extend(['aws', 'access', 'key', 'id'])
    elif secret.secret_type == SecretType.AWS_SECRET_KEY:
        keywords.extend(['aws', 'secret', 'key'])
    elif secret.secret_type == SecretType.GITHUB_TOKEN:
        keywords.extend(['github', 'token', 'gh'])
    elif secret.secret_type == SecretType.DATABASE_URL:
        keywords.extend(['database', 'db', 'url', 'postgres', 'mysql', 'mongodb'])
    
    return list(set(keywords))


def is_related(ref: ConfigReference, secret_keywords: List[str]) -> bool:
    """Check if a config reference is related to the secret."""
    var_lower = ref.variable_name.lower()
    return any(keyword in var_lower for keyword in secret_keywords)


def calculate_risk_score(
    secret: SecretFinding,
    config_refs: List[ConfigReference],
    affected_services: List[ServiceNode]
) -> int:
    """Calculate blast radius risk score (0-100)."""
    score = 0
    
    # Base score by secret type
    type_scores = {
        SecretType.AWS_ACCESS_KEY: 30,
        SecretType.AWS_SECRET_KEY: 40,
        SecretType.GITHUB_TOKEN: 35,
        SecretType.SLACK_TOKEN: 25,
        SecretType.DATABASE_URL: 45,
        SecretType.API_KEY: 30,
        SecretType.PRIVATE_KEY: 50,
        SecretType.JWT_SECRET: 40,
        SecretType.GENERIC: 20,
    }
    score += type_scores.get(secret.secret_type, 20)
    
    # Add points for hardcoded references
    hardcoded_count = sum(1 for r in config_refs if r.is_hardcoded)
    score += min(hardcoded_count * 10, 30)
    
    # Add points for number of affected services
    score += min(len(affected_services) * 5, 25)
    
    # Add points for entropy (high entropy = more likely real secret)
    if secret.entropy > 4.0:
        score += 10
    elif secret.entropy > 3.0:
        score += 5
    
    return min(score, 100)


def score_to_risk_level(score: int) -> str:
    """Convert score to risk level."""
    if score >= 75:
        return "CRITICAL"
    elif score >= 50:
        return "HIGH"
    elif score >= 25:
        return "MEDIUM"
    return "LOW"


def build_blast_radius_graph(results: List[BlastRadiusResult]) -> nx.DiGraph:
    """Build a NetworkX graph representing the blast radius."""
    G = nx.DiGraph()
    
    for result in results:
        secret_node = f"secret:{result.secret.rule_id}:{result.secret.file_path}:{result.secret.line_number}"
        G.add_node(secret_node, type="secret", label=result.secret.rule_id, risk=result.risk_level)
        
        for ref in result.config_references:
            config_node = f"config:{ref.config_file}:{ref.variable_name}"
            G.add_node(config_node, type="config", label=f"{ref.config_type}:{ref.variable_name}")
            G.add_edge(secret_node, config_node, relation="referenced_in")
            
            if ref.service_name:
                svc_node = f"service:{ref.service_name}"
                G.add_node(svc_node, type="service", label=ref.service_name)
                G.add_edge(config_node, svc_node, relation="used_by")
        
        for svc in result.affected_services:
            svc_node = f"service:{svc.name}"
            if svc_node in G:
                for dep in svc.depends_on:
                    dep_node = f"service:{dep}"
                    if dep_node in G:
                        G.add_edge(svc_node, dep_node, relation="depends_on")
    
    return G