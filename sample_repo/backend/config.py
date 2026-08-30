import os
import boto3
import jwt
import psycopg2
import redis

# AWS Configuration - use env vars only
AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")

# Database Configuration - use env var only
DATABASE_URL = os.getenv("DATABASE_URL")

# JWT Configuration - use env var only
JWT_SECRET = os.getenv("JWT_SECRET")

# Redis Configuration - use env var only
REDIS_URL = os.getenv("REDIS_URL")

# GitHub API - use env var only
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

# Slack - use env var only
SLACK_TOKEN = os.getenv("SLACK_TOKEN")

# API Keys - use env var only
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY")

def get_db_connection():
    return psycopg2.connect(DATABASE_URL)

def get_redis_client():
    return redis.from_url(REDIS_URL)

def get_s3_client():
    return boto3.client(
        's3',
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    )

def create_jwt_token(payload: dict) -> str:
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')

def verify_jwt_token(token: str) -> dict:
    return jwt.decode(token, JWT_SECRET, algorithms=['HS256'])