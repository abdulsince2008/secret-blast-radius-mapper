"""Data models for Secret Blast-Radius Mapper."""
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from enum import Enum


class SecretType(Enum):
    """Types of secrets we can detect."""
    AWS_ACCESS_KEY = "aws_access_key"
    AWS_SECRET_KEY = "aws_secret_key"
    GITHUB_TOKEN = "github_token"
    SLACK_TOKEN = "slack_token"
    DATABASE_URL = "database_url"
    API_KEY = "api_key"
    PRIVATE_KEY = "private_key"
    JWT_SECRET = "jwt_secret"
    GENERIC = "generic"


@dataclass
class SecretFinding:
    """A single secret finding from gitleaks."""
    file_path: str
    line_number: int
    secret_type: SecretType
    rule_id: str
    entropy: float
    secret_preview: str  # Masked preview
    commit_hash: Optional[str] = None
    author: Optional[str] = None
    date: Optional[str] = None
    match: str = ""


@dataclass
class ConfigReference:
    """A reference to a secret in a config file."""
    config_file: str
    config_type: str  # .env, docker-compose, k8s, etc.
    service_name: Optional[str]
    variable_name: str
    line_number: int
    is_hardcoded: bool = False
    referenced_secret: Optional[str] = None  # The actual secret value if hardcoded


@dataclass
class ServiceNode:
    """A service in the dependency graph."""
    name: str
    type: str  # microservice, database, api, etc.
    config_files: List[str] = field(default_factory=list)
    environment_variables: List[str] = field(default_factory=list)
    depends_on: List[str] = field(default_factory=list)


@dataclass
class BlastRadiusResult:
    """Complete blast radius analysis for a secret."""
    secret: SecretFinding
    origin_commit: Optional[str]
    introduced_by: Optional[str]
    introduced_date: Optional[str]
    config_references: List[ConfigReference] = field(default_factory=list)
    affected_services: List[ServiceNode] = field(default_factory=list)
    blast_radius_score: int = 0  # 0-100
    risk_level: str = "UNKNOWN"  # CRITICAL, HIGH, MEDIUM, LOW

    def to_dict(self) -> Dict[str, Any]:
        return {
            "secret": {
                "file": self.secret.file_path,
                "line": self.secret.line_number,
                "type": self.secret.secret_type.value,
                "rule": self.secret.rule_id,
                "preview": self.secret.secret_preview,
                "commit": self.secret.commit_hash,
                "author": self.secret.author,
                "date": self.secret.date,
            },
            "origin": {
                "commit": self.origin_commit,
                "author": self.introduced_by,
                "date": self.introduced_date,
            },
            "config_references": [
                {
                    "file": r.config_file,
                    "type": r.config_type,
                    "service": r.service_name,
                    "variable": r.variable_name,
                    "line": r.line_number,
                    "hardcoded": r.is_hardcoded,
                }
                for r in self.config_references
            ],
            "affected_services": [
                {
                    "name": s.name,
                    "type": s.type,
                    "config_files": s.config_files,
                    "env_vars": s.environment_variables,
                    "depends_on": s.depends_on,
                }
                for s in self.affected_services
            ],
            "blast_radius_score": self.blast_radius_score,
            "risk_level": self.risk_level,
        }