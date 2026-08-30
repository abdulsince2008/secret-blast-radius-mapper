#!/usr/bin/env bash
# Setup script for the included sample repository
# Run this once after cloning to initialize sample_repo as a git repo with history

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SAMPLE_REPO="${SCRIPT_DIR}/sample_repo"

if [ ! -d "${SAMPLE_REPO}" ]; then
    echo "Error: sample_repo not found at ${SAMPLE_REPO}"
    exit 1
fi

if [ -d "${SAMPLE_REPO}/.git" ]; then
    echo "sample_repo already initialized as git repository"
    exit 0
fi

echo "Initializing sample_repo as git repository..."
cd "${SAMPLE_REPO}"
git init
git config user.email "test@example.com"
git config user.name "Test User"
git add .
git commit -m "Initial commit with secrets"

# Add a second commit to show history (remove some hardcoded secrets)
# This simulates a real scenario where secrets were added then partially removed
sed -i 's/AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")/AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")/' backend/config.py
sed -i 's/AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI\/K7MDENG\/bPxRfiCYEXAMPLEKEY")/AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")/' backend/config.py
sed -i 's/DATABASE_URL = os.getenv("DATABASE_URL", "postgresql:\/\/user:supersecretpassword123@localhost:5432\/myapp")/DATABASE_URL = os.getenv("DATABASE_URL")/' backend/config.py
sed -i 's/JWT_SECRET = os.getenv("JWT_SECRET", "my-super-secret-jwt-key-that-is-very-long-and-random")/JWT_SECRET = os.getenv("JWT_SECRET")/' backend/config.py
sed -i 's/REDIS_URL = os.getenv("REDIS_URL", "redis:\/\/:redispassword123@localhost:6379")/REDIS_URL = os.getenv("REDIS_URL")/' backend/config.py
sed -i 's/GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "ghp_abcdefghijklmnopqrstuvwxyz1234567890abcd")/GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")/' backend/config.py
sed -i 's/SLACK_TOKEN = os.getenv("SLACK_TOKEN", "xoxb-123456789012-abcdefghijklmnopqrstuvwxyz")/SLACK_TOKEN = os.getenv("SLACK_TOKEN")/' backend/config.py
sed -i 's/STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "sk_live_abcdefghijklmnopqrstuvwx")/STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY")/' backend/config.py

git add backend/config.py
git commit -m "Remove hardcoded secrets from config.py"

echo "sample_repo initialized with 2 commits"
echo "You can now run: python -m src.cli sample_repo"