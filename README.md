# Secure Token Gateway SOC

A Zero‑Trust authentication gateway with Proof‑of‑Possession JWTs,
device authentication, replay protection and a real‑time SOC dashboard.

## Features

- Device based authentication
- Proof of Possession JWT
- Token rotation
- Replay attack detection
- Redis security controls
- Threat risk scoring
- SOC dashboard visualization
- Attack simulation client

## Architecture

Client (WebCrypto)
       ↓
FastAPI Secure Gateway
       ↓
Redis (replay detection)
MongoDB (audit logs)
       ↓
SOC Dashboard (React)
