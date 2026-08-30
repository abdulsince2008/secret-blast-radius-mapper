"""Git history tracing for secret origins."""
import git
from pathlib import Path
from typing import Optional, Tuple, List
from src.models import SecretFinding


def find_secret_origin(repo_path: Path, finding: SecretFinding) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Find the commit where a secret was first introduced.
    
    Returns:
        Tuple of (commit_hash, author, date) or (None, None, None)
    """
    try:
        repo = git.Repo(repo_path)
    except Exception:
        return None, None, None
    
    file_path = finding.file_path
    secret_preview = finding.secret_preview.replace("*", "")  # Remove masking for search
    
    # If we already have commit info from blame, use that as starting point
    if finding.commit_hash:
        try:
            commit = repo.commit(finding.commit_hash)
            return commit.hexsha[:8], commit.author.name, commit.authored_datetime.isoformat()
        except Exception:
            pass
    
    # Search git log for when this secret first appeared
    # Use git log -p to search for the secret in diffs
    try:
        # Search for commits that added the secret
        log_cmd = [
            "git", "log", "--all", "--full-history", "-p", "-S", secret_preview,
            "--", file_path
        ]
        result = repo.git.execute(log_cmd, with_extended_output=True)
        
        if result[0] == 0 and result[1].strip():
            # Parse the output to find the first commit that introduced it
            output = result[1]
            commits = parse_git_log_output(output)
            if commits:
                first_commit = commits[-1]  # Last in list is oldest
                return first_commit["hash"], first_commit["author"], first_commit["date"]
    except Exception:
        pass
    
    # Fallback: check the current blame
    try:
        blame = repo.blame("HEAD", file_path, L=f"{finding.line_number},{finding.line_number}")
        if blame:
            commit, _ = blame[0]
            return commit.hexsha[:8], commit.author.name, commit.authored_datetime.isoformat()
    except Exception:
        pass
    
    return None, None, None


def parse_git_log_output(output: str) -> List[dict]:
    """Parse git log -p output to extract commit info."""
    commits = []
    current_commit = {}
    
    for line in output.split("\n"):
        if line.startswith("commit "):
            if current_commit:
                commits.append(current_commit)
            current_commit = {"hash": line.split()[1][:8]}
        elif line.startswith("Author: "):
            current_commit["author"] = line[8:].strip()
        elif line.startswith("Date: "):
            current_commit["date"] = line[6:].strip()
    
    if current_commit:
        commits.append(current_commit)
    
    return commits


def get_file_history(repo_path: Path, file_path: str, max_commits: int = 50) -> List[dict]:
    """Get recent commit history for a file."""
    try:
        repo = git.Repo(repo_path)
        commits = list(repo.iter_commits(paths=file_path, max_count=max_commits))
        return [
            {
                "hash": c.hexsha[:8],
                "author": c.author.name,
                "date": c.authored_datetime.isoformat(),
                "message": c.message.strip(),
            }
            for c in commits
        ]
    except Exception:
        return []