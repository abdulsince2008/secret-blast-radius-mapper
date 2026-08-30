"""Secret detection using gitleaks subprocess."""
import json
import subprocess
import shutil
from pathlib import Path
from typing import List, Optional
from src.models import SecretFinding, SecretType


SECRET_TYPE_MAP = {
    "aws-access-key-id": SecretType.AWS_ACCESS_KEY,
    "aws-access-token": SecretType.AWS_ACCESS_KEY,
    "aws-secret-access-key": SecretType.AWS_SECRET_KEY,
    "github-pat": SecretType.GITHUB_TOKEN,
    "github-token": SecretType.GITHUB_TOKEN,
    "slack-token": SecretType.SLACK_TOKEN,
    "slack-legacy-bot-token": SecretType.SLACK_TOKEN,
    "database-url": SecretType.DATABASE_URL,
    "api-key": SecretType.API_KEY,
    "generic-api-key": SecretType.API_KEY,
    "private-key": SecretType.PRIVATE_KEY,
    "jwt-secret": SecretType.JWT_SECRET,
    "stripe-access-token": SecretType.API_KEY,
}


def map_rule_to_type(rule_id: str) -> SecretType:
    """Map gitleaks rule ID to our SecretType enum."""
    rule_lower = rule_id.lower()
    for key, stype in SECRET_TYPE_MAP.items():
        if key in rule_lower:
            return stype
    return SecretType.GENERIC


def mask_secret(secret: str, visible_chars: int = 4) -> str:
    """Mask a secret for display."""
    if len(secret) <= visible_chars * 2:
        return "*" * len(secret)
    return secret[:visible_chars] + "*" * (len(secret) - visible_chars * 2) + secret[-visible_chars:]


def run_gitleaks(repo_path: Path, config_path: Optional[Path] = None) -> List[SecretFinding]:
    """
    Run gitleaks on a repository and return findings.
    
    Args:
        repo_path: Path to the git repository
        config_path: Optional path to gitleaks config file
        
    Returns:
        List of SecretFinding objects
    """
    # Check if gitleaks is installed
    if not shutil.which("gitleaks"):
        raise RuntimeError(
            "gitleaks not found in PATH. Install it: "
            "https://github.com/gitleaks/gitleaks#installation"
        )
    
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp:
        report_path = tmp.name
    
    try:
        cmd = ["gitleaks", "detect", "--source", str(repo_path), "--report-format", "json", 
               "--no-banner", "--redact=0", "--report-path", report_path]
        
        if config_path and config_path.exists():
            cmd.extend(["--config", str(config_path)])
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
                cwd=repo_path
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError("gitleaks timed out after 120 seconds")
        except FileNotFoundError:
            raise RuntimeError("gitleaks not found. Please install gitleaks.")
        
        # gitleaks returns 1 when leaks found, 0 when clean
        if result.returncode not in (0, 1):
            raise RuntimeError(f"gitleaks failed: {result.stderr}")
        
        # Parse JSON output from report file
        findings = []
        try:
            report_content = Path(report_path).read_text()
            if report_content.strip():
                leaks = json.loads(report_content)
                for leak in leaks:
                    finding = SecretFinding(
                        file_path=leak.get("File", ""),
                        line_number=leak.get("StartLine", 0),
                        secret_type=map_rule_to_type(leak.get("RuleID", "")),
                        rule_id=leak.get("RuleID", ""),
                        entropy=leak.get("Entropy", 0.0),
                        secret_preview=mask_secret(leak.get("Secret", "")),
                        match=leak.get("Match", ""),
                    )
                    findings.append(finding)
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Failed to parse gitleaks output: {e}")
        except FileNotFoundError:
            pass  # No report file means no findings
        
        return findings
    finally:
        # Clean up temp file
        try:
            Path(report_path).unlink(missing_ok=True)
        except Exception:
            pass


def enrich_with_git_info(repo_path: Path, findings: List[SecretFinding]) -> List[SecretFinding]:
    """Enrich findings with git commit info using git blame."""
    try:
        import git
        repo = git.Repo(repo_path)
    except Exception:
        return findings  # Return as-is if git not available
    
    for finding in findings:
        try:
            # Get blame info for the specific line
            blame = repo.blame("HEAD", finding.file_path, L=f"{finding.line_number},{finding.line_number}")
            if blame:
                commit, _ = blame[0]
                finding.commit_hash = commit.hexsha[:8]
                finding.author = commit.author.name
                finding.date = commit.authored_datetime.isoformat()
        except Exception:
            pass  # Keep original if blame fails
    
    return findings