# Fixture repo_a — Dockerfile with hardcoded secret and TLS disabled
# This file deliberately contains real vulnerabilities to test detection.

FROM python:3.11-slim

# Real hardcoded secret — must be detected by regex layer
ENV STRIPE_SECRET_KEY=test_sec_key_ABCDEFGHIJKLMNOPQRSTUVWX

# TLS disabled — must be detected as a separate finding  
ENV NODE_TLS_REJECT_UNAUTHORIZED=0

RUN pip install requests
