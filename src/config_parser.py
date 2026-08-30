"""Config file parsing for secret references."""
import os
import re
import yaml
from pathlib import Path
from typing import List, Optional, Dict, Any
from src.models import ConfigReference


ENV_VAR_PATTERN = re.compile(r'^([A-Z_][A-Z0-9_]*)\s*=\s*(.*)$')
SECRET_KEYWORDS = [
    'key', 'secret', 'token', 'password', 'passwd', 'pwd', 'api_key',
    'apikey', 'access_key', 'secret_key', 'private_key', 'jwt',
    'database_url', 'db_url', 'connection_string', 'conn_str'
]


def is_secret_variable(name: str) -> bool:
    """Check if a variable name looks like a secret."""
    name_lower = name.lower()
    return any(keyword in name_lower for keyword in SECRET_KEYWORDS)


def parse_env_file(file_path: Path) -> List[ConfigReference]:
    """Parse a .env file for secret references."""
    references = []
    
    try:
        content = file_path.read_text()
    except Exception:
        return references
    
    for line_num, line in enumerate(content.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        
        match = ENV_VAR_PATTERN.match(line)
        if match:
            var_name, var_value = match.groups()
            var_value = var_value.strip().strip('"\'')
            
            # Check if this looks like a secret
            if is_secret_variable(var_name) or (var_value and len(var_value) > 20):
                references.append(ConfigReference(
                    config_file=str(file_path),
                    config_type="env",
                    service_name=None,
                    variable_name=var_name,
                    line_number=line_num,
                    is_hardcoded=bool(var_value and not var_value.startswith("${") and not var_value.startswith("$")),
                    referenced_secret=var_value if var_value and not var_value.startswith("${") and not var_value.startswith("$") else None,
                ))
    
    return references


def parse_docker_compose(file_path: Path) -> List[ConfigReference]:
    """Parse docker-compose.yml for secret references."""
    references = []
    
    try:
        content = yaml.safe_load(file_path.read_text())
    except Exception:
        return references
    
    if not content or 'services' not in content:
        return references
    
    for service_name, service_config in content['services'].items():
        # Check environment variables
        env_vars = service_config.get('environment', {})
        if isinstance(env_vars, list):
            # Handle list format: ["VAR=value", "VAR2=value2"]
            for idx, env in enumerate(env_vars):
                if '=' in env:
                    var_name, var_value = env.split('=', 1)
                    if is_secret_variable(var_name):
                        references.append(ConfigReference(
                            config_file=str(file_path),
                            config_type="docker-compose",
                            service_name=service_name,
                            variable_name=var_name.strip(),
                            line_number=idx + 1,  # Approximate
                            is_hardcoded=not var_value.strip().startswith("${"),
                            referenced_secret=var_value.strip() if not var_value.strip().startswith("${") else None,
                        ))
        elif isinstance(env_vars, dict):
            for var_name, var_value in env_vars.items():
                if is_secret_variable(var_name):
                    references.append(ConfigReference(
                        config_file=str(file_path),
                        config_type="docker-compose",
                        service_name=service_name,
                        variable_name=var_name,
                        line_number=0,  # YAML doesn't preserve line numbers easily
                        is_hardcoded=not str(var_value).startswith("${"),
                        referenced_secret=str(var_value) if not str(var_value).startswith("${") else None,
                    ))
        
        # Check secrets section
        secrets = service_config.get('secrets', [])
        for secret in secrets:
            if isinstance(secret, str):
                references.append(ConfigReference(
                    config_file=str(file_path),
                    config_type="docker-compose",
                    service_name=service_name,
                    variable_name=secret,
                    line_number=0,
                    is_hardcoded=False,
                ))
            elif isinstance(secret, dict) and 'source' in secret:
                references.append(ConfigReference(
                    config_file=str(file_path),
                    config_type="docker-compose",
                    service_name=service_name,
                    variable_name=secret['source'],
                    line_number=0,
                    is_hardcoded=False,
                ))
    
    return references


def parse_kubernetes(file_path: Path) -> List[ConfigReference]:
    """Parse Kubernetes YAML files for secret references."""
    references = []
    
    try:
        docs = list(yaml.safe_load_all(file_path.read_text()))
    except Exception:
        return references
    
    for doc in docs:
        if not doc:
            continue
        
        kind = doc.get('kind', '')
        metadata = doc.get('metadata', {})
        name = metadata.get('name', 'unknown')
        namespace = metadata.get('namespace', 'default')
        service_name = f"{namespace}/{name}"
        
        if kind == 'Secret':
            data = doc.get('data', {})
            string_data = doc.get('stringData', {})
            
            for key in data.keys():
                references.append(ConfigReference(
                    config_file=str(file_path),
                    config_type="kubernetes",
                    service_name=service_name,
                    variable_name=key,
                    line_number=0,
                    is_hardcoded=True,
                ))
            
            for key, value in string_data.items():
                references.append(ConfigReference(
                    config_file=str(file_path),
                    config_type="kubernetes",
                    service_name=service_name,
                    variable_name=key,
                    line_number=0,
                    is_hardcoded=True,
                    referenced_secret=value,
                ))
        
        elif kind in ('Deployment', 'StatefulSet', 'DaemonSet', 'Pod', 'CronJob'):
            # Check env vars in containers
            spec = doc.get('spec', {})
            if kind == 'CronJob':
                spec = spec.get('jobTemplate', {}).get('spec', {}).get('template', {}).get('spec', {})
            elif 'template' in spec:
                spec = spec['template'].get('spec', {})
            
            containers = spec.get('containers', [])
            for container in containers:
                env_vars = container.get('env', [])
                for env in env_vars:
                    var_name = env.get('name', '')
                    if is_secret_variable(var_name):
                        value_from = env.get('valueFrom', {})
                        secret_ref = value_from.get('secretKeyRef', {})
                        config_map_ref = value_from.get('configMapKeyRef', {})
                        
                        references.append(ConfigReference(
                            config_file=str(file_path),
                            config_type="kubernetes",
                            service_name=service_name,
                            variable_name=var_name,
                            line_number=0,
                            is_hardcoded='value' in env,
                            referenced_secret=env.get('value') if 'value' in env else None,
                        ))
                
                # Check envFrom
                env_from = container.get('envFrom', [])
                for ef in env_from:
                    secret_ref = ef.get('secretRef', {})
                    if secret_ref:
                        references.append(ConfigReference(
                            config_file=str(file_path),
                            config_type="kubernetes",
                            service_name=service_name,
                            variable_name=secret_ref.get('name', 'unknown'),
                            line_number=0,
                            is_hardcoded=False,
                        ))
    
    return references


def parse_github_actions(file_path: Path) -> List[ConfigReference]:
    """Parse GitHub Actions workflow files for secret references."""
    references = []
    
    try:
        content = yaml.safe_load(file_path.read_text())
    except Exception:
        return references
    
    if not content:
        return references
    
    # Check jobs
    jobs = content.get('jobs', {})
    for job_name, job_config in jobs.items():
        # Check env at job level
        env = job_config.get('env', {})
        for var_name, var_value in env.items():
            if is_secret_variable(var_name):
                references.append(ConfigReference(
                    config_file=str(file_path),
                    config_type="github-actions",
                    service_name=job_name,
                    variable_name=var_name,
                    line_number=0,
                    is_hardcoded=not str(var_value).startswith("${{ secrets."),
                    referenced_secret=str(var_value) if not str(var_value).startswith("${{ secrets.") else None,
                ))
        
        # Check steps
        steps = job_config.get('steps', [])
        for step in steps:
            step_env = step.get('env', {})
            for var_name, var_value in step_env.items():
                if is_secret_variable(var_name):
                    references.append(ConfigReference(
                        config_file=str(file_path),
                        config_type="github-actions",
                        service_name=f"{job_name}/{step.get('name', 'unnamed')}",
                        variable_name=var_name,
                        line_number=0,
                        is_hardcoded=not str(var_value).startswith("${{ secrets."),
                        referenced_secret=str(var_value) if not str(var_value).startswith("${{ secrets.") else None,
                    ))
    
    return references


def find_config_files(repo_path: Path) -> List[Path]:
    """Find all config files in the repository."""
    patterns = [
        "**/.env*",
        "**/docker-compose*.yml",
        "**/docker-compose*.yaml",
        "**/docker-compose*.yaml",
        "**/k8s/**/*.yaml",
        "**/k8s/**/*.yml",
        "**/kubernetes/**/*.yaml",
        "**/kubernetes/**/*.yml",
        "**/*.k8s.yaml",
        "**/*.k8s.yml",
        "**/.github/workflows/*.yml",
        "**/.github/workflows/*.yaml",
        "**/helm/**/*.yaml",
        "**/helm/**/*.yml",
        "**/values*.yaml",
        "**/values*.yml",
    ]
    
    files = []
    for pattern in patterns:
        files.extend(repo_path.glob(pattern))
    
    # Deduplicate
    unique_files = []
    seen = set()
    for f in files:
        if f not in seen:
            seen.add(f)
            unique_files.append(f)
    
    return unique_files


def parse_all_configs(repo_path: Path) -> List[ConfigReference]:
    """Parse all config files in a repository."""
    all_refs = []
    config_files = find_config_files(repo_path)
    
    for config_file in config_files:
        suffix = config_file.suffix.lower()
        name = config_file.name.lower()
        
        if name.startswith('.env'):
            all_refs.extend(parse_env_file(config_file))
        elif 'docker-compose' in name:
            all_refs.extend(parse_docker_compose(config_file))
        elif suffix in ('.yaml', '.yml'):
            # Determine type by path
            path_str = str(config_file).lower()
            if 'k8s' in path_str or 'kubernetes' in path_str or '.k8s.' in path_str:
                all_refs.extend(parse_kubernetes(config_file))
            elif '.github/workflows' in path_str:
                all_refs.extend(parse_github_actions(config_file))
            elif 'helm' in path_str or name.startswith('values'):
                all_refs.extend(parse_kubernetes(config_file))  # Helm uses similar structure
    
    return all_refs