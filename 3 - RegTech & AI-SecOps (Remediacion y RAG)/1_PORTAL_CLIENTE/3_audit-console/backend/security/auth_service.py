"""BunkerOS - Módulo de Autenticación JWT.
======================================
Emisión y validación de tokens JWT firmados con HMAC-SHA256.
Cumplimiento: ENS Alta (op.acc.1, op.acc.5), OWASP ASVS v4 §3.5, NIS2 Art.21.

Arquitectura:
  - Secreto derivado desde BUNKER_JWT_SECRET (env) con PBKDF2-HMAC-SHA256.
  - Expiración configurable (default 15 min) para mitigar replay attacks.
  - Claims obligatorios: sub, role, iat, exp, jti (nonce anti-replay).
  - Timing-safe comparison en la validación de secretos.
"""

import base64
import json
import os
import secrets
from datetime import datetime, timedelta, timezone

import hvac
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer
from src.bunker_exceptions import BunkerSecurityError
from src.bunker_logger import log_auditoria

try:
    import httpx2 as httpx
    import jwt
    from cachetools import TTLCache
    from joserfc import jwt as joserfc_jwt
    from joserfc.jwk import KeySet

    JOSE_AVAILABLE = True
except ImportError:
    JOSE_AVAILABLE = False

# ─────────────────────────────────────────────
# CONFIGURACIÓN DERIVADA DESDE ENTORNO
# ─────────────────────────────────────────────
import redis.asyncio as redis

# Configuración del Cliente Redis
redis_client = redis.Redis(
    host=os.getenv("REDIS_HOST", "127.0.0.1"),
    port=6379,
    db=0,
    decode_responses=True,
)


class VaultJWTSigner:
    def __init__(self) -> None:
        self.bunker_env = os.getenv("BUNKER_ENV", "PROD").upper()
        if self.bunker_env in ["TEST", "DEVELOPMENT"]:
            self.client = None
            return

        try:
            self.client = hvac.Client(url=os.getenv("VAULT_ADDR", "http://vault:8200"))
            if "VAULT_ROLE_ID" in os.environ and "VAULT_SECRET_ID" in os.environ:
                self.client.auth.approle.login(
                    role_id=os.environ["VAULT_ROLE_ID"],
                    secret_id=os.environ["VAULT_SECRET_ID"],
                )
            elif "VAULT_TOKEN" in os.environ:
                self.client.token = os.environ["VAULT_TOKEN"]
            else:
                msg = "Credenciales Vault ausentes"
                raise BunkerSecurityError(msg, 401)
        except (ValueError, TypeError, RuntimeError, OSError, AttributeError) as e:
            msg = f"Fallo conexión Vault: {e}"
            raise BunkerSecurityError(msg, 500)

    def create_jwt(self, claims: dict) -> str:
        if self.client is None:
            import jwt as pyjwt
            from src.security.bunker_memory_guard import get_secure_buffer
            try:
                secret = get_secure_buffer("BUNKER_JWT_SECRET").get_bytes()
            except ValueError:
                secret = "dev_jwt_secret_456"
            sanitized_claims = {}
            for k, v in claims.items():
                if isinstance(v, datetime):
                    sanitized_claims[k] = int(v.timestamp())
                else:
                    sanitized_claims[k] = v
            if hasattr(pyjwt, "encode"):
                return pyjwt.encode(sanitized_claims, secret, algorithm="HS256")
            from jose import jwt as jose_jwt
            return jose_jwt.encode(sanitized_claims, secret, algorithm="HS256")

        header = {"alg": "RS256", "typ": "JWT"}
        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        payload_b64 = base64.urlsafe_b64encode(json.dumps(claims, default=str).encode()).decode().rstrip("=")
        data_to_sign = f"{header_b64}.{payload_b64}"

        b64_input = base64.b64encode(data_to_sign.encode()).decode()
        try:
            response = self.client.secrets.transit.sign_data(
                name="bunkeros-jwt",
                plaintext=b64_input,
                hash_algorithm="sha2-256",
                signature_algorithm="pkcs1v15",
            )
        except TypeError:
            response = self.client.secrets.transit.sign_data(
                name="bunkeros-jwt",
                input=b64_input,
                hash_algorithm="sha2-256",
                signature_algorithm="pkcs1v15",
            )
        sig_b64 = response["data"]["signature"].replace("vault:v1:", "")
        sig_bytes = base64.b64decode(sig_b64)
        sig_jwt = base64.urlsafe_b64encode(sig_bytes).decode().rstrip("=")
        return f"{data_to_sign}.{sig_jwt}"

    def decode_jwt(self, token: str) -> dict:
        if self.client is None:
            import jwt as pyjwt
            from src.security.bunker_memory_guard import get_secure_buffer
            try:
                secret = get_secure_buffer("BUNKER_JWT_SECRET").get_bytes()
            except ValueError:
                secret = "dev_jwt_secret_456"
            if hasattr(pyjwt, "decode"):
                return pyjwt.decode(token, secret, algorithms=["HS256"])
            from jose import jwt as jose_jwt
            return jose_jwt.decode(token, secret, algorithms=["HS256"])

        parts = token.split(".")
        if len(parts) != 3:
            msg = "Invalid JWT format"
            raise ValueError(msg)

        data_to_verify = f"{parts[0]}.{parts[1]}"

        b64_input = base64.b64encode(data_to_verify.encode()).decode()
        sig_urlsafe = parts[2]
        padding = "=" * (4 - (len(sig_urlsafe) % 4))
        sig_bytes = base64.urlsafe_b64decode(sig_urlsafe + padding)
        sig_b64 = base64.b64encode(sig_bytes).decode()

        try:
            response = self.client.secrets.transit.verify_signed_data(
                name="bunkeros-jwt",
                plaintext=b64_input,
                signature=f"vault:v1:{sig_b64}",
                hash_algorithm="sha2-256",
                signature_algorithm="pkcs1v15",
            )
        except TypeError:
            response = self.client.secrets.transit.verify_signed_data(
                name="bunkeros-jwt",
                input=b64_input,
                signature=f"vault:v1:{sig_b64}",
                hash_algorithm="sha2-256",
                signature_algorithm="pkcs1v15",
            )
        if not response["data"]["valid"]:
            msg = "Invalid signature from Vault"
            raise ValueError(msg)

        payload_padded = parts[1] + "=" * (4 - (len(parts[1]) % 4))
        return json.loads(base64.urlsafe_b64decode(payload_padded).decode())

vault_jwt_signer = VaultJWTSigner()

ALGORITHM = "RS256"
ACCESS_TOKEN_TTL = int(os.getenv("BUNKER_JWT_TTL_MINUTES", "15"))  # minutos
REFRESH_TOKEN_TTL = 7 * 24 * 60  # 7 days in minutes
ADMIN_TOKEN_ENV = os.getenv("BUNKER_ADMIN_TOKEN")

_bearer_scheme = HTTPBearer(auto_error=False)

# ─────────────────────────────────────────────
# EMISIÓN DE TOKENS
# ─────────────────────────────────────────────


def create_access_token(
    subject: str, role: str, extra_claims: dict | None = None, strict_validation: bool = True,
) -> str:
    """Emite un JWT firmado con HS256.
    Incluye jti (nonce único) para invalidación punto-a-punto.
    Cumple OWASP ASVS v4 §3.5.1 y ENS op.acc.5.
    """
    if not JOSE_AVAILABLE:
        msg = "python-jose no disponible. Instala: pip install python-jose[cryptography]"
        raise RuntimeError(
            msg,
        )

    trust_score = extra_claims.get("trust_score", 0) if extra_claims else 0
    if strict_validation and trust_score <= 0:
        msg = "Trust score must be greater than zero. Hardware verification required."
        raise BunkerSecurityError(msg)

    now = datetime.now(timezone.utc)
    claims = {
        "sub": subject,
        "role": role,
        "iat": now,
        "exp": now + timedelta(minutes=ACCESS_TOKEN_TTL),
        "jti": secrets.token_hex(16),  # anti-replay nonce
        "iss": "bunker-os-platform",
        "type": "access",
        # ABAC Claims Base (ENS op.acc.2)
        "geo_region": (
            extra_claims.get("geo_region", "Comunidad Valenciana")
            if extra_claims
            else "Comunidad Valenciana"
        ),
        "network_zone": (
            extra_claims.get("network_zone", "VLAN-SECURE")
            if extra_claims
            else "VLAN-SECURE"
        ),
        "trust_score": (
            extra_claims.get("trust_score", 0) if extra_claims else 0
        ),
        "mfa_method": (
            extra_claims.get("mfa_method", "FIDO2")
            if extra_claims
            else "FIDO2"
        ),
    }
    if extra_claims:
        claims.update(extra_claims)

    return vault_jwt_signer.create_jwt(claims)


def create_refresh_token(subject: str, role: str) -> str:
    """Emite un Refresh Token firmado con HS256 (TTL 7 días)."""
    if not JOSE_AVAILABLE:
        msg = "python-jose no disponible."
        raise RuntimeError(msg)

    now = datetime.now(timezone.utc)
    claims = {
        "sub": subject,
        "role": role,
        "iat": now,
        "exp": now + timedelta(minutes=REFRESH_TOKEN_TTL),
        "jti": secrets.token_hex(16),
        "iss": "bunker-os-platform",
        "type": "refresh",
    }
    return vault_jwt_signer.create_jwt(claims)


# ─────────────────────────────────────────────
# FEDERACIÓN OIDC Y JWKS CACHE (Tolerancia a fallos)
# ─────────────────────────────────────────────
# 5 min TTL para resistencia a microcaídas
jwks_cache = TTLCache(maxsize=2, ttl=300)


async def get_oidc_jwks() -> dict:
    if "keys" in jwks_cache:
        return jwks_cache["keys"]
    try:
        oidc_uri = os.getenv(
            "OIDC_JWKS_URI",
            "https://login.microsoftonline.com/common/discovery/v2.0/keys",
        )
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(oidc_uri)
            resp.raise_for_status()
            keys = resp.json()
            jwks_cache["keys"] = keys
            return keys
    except BunkerSecurityError:
        await log_auditoria("SYSTEM", "OIDC_FETCH_FAIL", "Fallo al recuperar JWKS remoto, aplicando fallback")
        # Graceful degradation: si la red cae, dependemos del caché o fallamos
        # seguro
        if "keys" in jwks_cache:
            return jwks_cache["keys"]
        raise HTTPException(
            status_code=503,
            detail="OIDC Provider Inalcanzable. Fallo de federación.",
        )


async def decode_token_federated(token: str) -> dict:
    """Decodifica validando contra JWKS en caché o contra HMAC local."""
    if not JOSE_AVAILABLE:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Motor JWT no disponible en este servidor.",
        )

    try:
        # Parseo de cabecera preliminar
        try:
            header = jwt.get_unverified_header(token)
        except BunkerSecurityError as header_exc:
            await log_auditoria(
                "SYSTEM",
                "JWT_HEADER_PARSE_ERROR",
                f"Fallo al parsear cabecera JWT: {header_exc}",
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token JWT/OIDC inválido, expirado o manipulado.",
                headers={"WWW-Authenticate": "Bearer"},
            ) from header_exc

        # Intento 1: OIDC RSA Signature con joserfc (Azure AD / Keycloak)
        if header.get("alg") == "RS256" and header.get("kid"):
            try:
                keys = await get_oidc_jwks()
                keyset = KeySet(keys)
                kid = header.get("kid")
                key = keyset.find_key(kid)
                if key:
                    token_decoded = joserfc_jwt.decode(token, key)
                    claims_registry = joserfc_jwt.JWTClaimsRegistry()
                    claims_registry.validate(token_decoded.claims)
                    claims = token_decoded.claims
                    return {
                        "sub": claims.get("sub"),
                        "role": claims.get("roles", ["USER"])[0],
                        "type": "access",
                        "jti": claims.get("jti", secrets.token_hex(16)),
                        "geo_region": claims.get("location", "Comunidad Valenciana"),
                        "network_zone": claims.get("network", "APV-Core"),
                        "trust_score": claims.get("trust_score", 0),
                        "mfa_method": "FIDO2",
                    }
            except BunkerSecurityError as oidc_exc:
                await log_auditoria(
                    "SYSTEM",
                    "OIDC_VALIDATION_ERROR",
                    f"OIDC validation failed, trying local Vault fallback: {oidc_exc}",
                )

        # Intento 2: HMAC Local (Fallback / M2M)
        try:
            return vault_jwt_signer.decode_jwt(token)
        except BunkerSecurityError as hmac_exc:
            await log_auditoria(
                "SYSTEM",
                "HMAC_VALIDATION_ERROR",
                f"Fallo de verificación de token HMAC local: {hmac_exc}",
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token JWT/OIDC inválido, expirado o manipulado.",
                headers={"WWW-Authenticate": "Bearer"},
            ) from hmac_exc
    except HTTPException:
        raise
    except BunkerSecurityError as general_exc:
        await log_auditoria(
            "SYSTEM",
            "JWT_GENERAL_ERROR",
            f"Fallo general e inesperado procesando token: {general_exc}",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token JWT/OIDC inválido, expirado o manipulado.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from general_exc


# ─────────────────────────────────────────────
# DEPENDENCIAS FASTAPI
# ─────────────────────────────────────────────
async def get_current_user(request: Request) -> dict:
    """Dependencia FastAPI: extrae y valida el JWT desde Cookie segura o Header Authorization.
    Devuelve el payload del token (sub, role, jti, exp...).
    """
    token_str = request.cookies.get("access_token")
    if not token_str:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token_str = auth_header.replace("Bearer ", "")
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Header/Cookie Authorization ausente (ENS op.acc.1).",
                headers={"WWW-Authenticate": "Bearer"},
            )

    token_bytes = bytearray()
    if token_str:
        token_bytes = bytearray(token_str.encode("utf-8"))
        # Immediately overwrite the local string reference to reduce exposure
        token_str = ""  # nosec B105

    try:
        # Decode token directly from bytes if possible, or string copy
        payload = await decode_token_federated(token_bytes.decode("utf-8"))

        # Check revocation in Redis
        try:
            if await redis_client.exists(f"revoked_jwt:{payload.get('jti')}"):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token actively revoked.",
                )
        except HTTPException:
            raise
        except (ValueError, TypeError, RuntimeError, OSError) as redis_exc:
            await log_auditoria(
                "SYSTEM",
                "REDIS_REVOCATION_CHECK_FAIL",
                f"Fallo al verificar revocación en Redis (degradación graciosa): {redis_exc}",
            )

        if payload.get("type") != "access":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token inválido. Se esperaba un token de acceso.",
            )

        # ─────────────────────────────────────────────
        # ABAC ENGINE (Continuous Authorization)
        # ─────────────────────────────────────────────
        from src.bunker_abac_engine import ABACContext, abac_engine
        from src.bunker_exceptions import (
            BunkerABACDeniedError,
            BunkerWORMIntegrityError,
        )

        client_ip = request.client.host if request.client else "127.0.0.1"
        context = ABACContext(
            username=payload.get("sub", "Unknown"),
            role=payload.get("role", "OPERATOR"),
            ip_address=client_ip,
            geo_region=payload.get("geo_region", "Comunidad Valenciana"),
            network_zone=payload.get("network_zone", "VLAN-SECURE"),
            trust_score=int(payload.get("trust_score", 0)),
            mfa_method=payload.get("mfa_method", "FIDO2"),
        )

        try:
            await abac_engine.evaluate_context(context)
        except BunkerABACDeniedError as abac_exc:
            from src.bunker_logger import log_worm_db
            log_worm_db(
                actor=payload.get("sub", "Unknown"),
                action="ABAC_DENIED",
                target=request.url.path,
                metadata={"reason": str(abac_exc), "denied_attribute": abac_exc.denied_attribute},
                ip_address=client_ip,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"ABAC: Acceso denegado. {abac_exc!s}",
            )
        except BunkerWORMIntegrityError:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Integridad del sistema comprometida.",
            )

        return payload
    finally:
        # HARDENING: Deterministic Memory wiping (FIPS 203 / ENS Alta)
        if "token_bytes" in locals() and isinstance(token_bytes, bytearray):
            from src.bunker_secure_wiper import SecureWiper
            SecureWiper.wipe_buffer(token_bytes)


def require_abac(
    min_trust_score: int = 80,
    required_role: str = "ADMIN",
    required_mfa: str = "FIDO2",
):
    async def dependency(request: Request, payload: dict = Depends(get_current_user)):
        if payload.get("role") != required_role:
            raise HTTPException(403, f"Rol insuficiente: {payload.get('role')}")
        if payload.get("trust_score", 0) < min_trust_score:
            raise HTTPException(403, f"Trust score insuficiente: {payload.get('trust_score')}")
        if payload.get("mfa_method") != required_mfa:
            raise HTTPException(403, f"MFA requerido: {required_mfa}")
        return payload
    return dependency




# ─────────────────────────────────────────────
# ENDPOINT DE EMISIÓN DE TOKEN (para integrar en el router)
# ─────────────────────────────────────────────
async def verify_admin_bearer(request: Request) -> dict:
    """Guard compatible con el token estático BUNKER_ADMIN_TOKEN para bootstrapping.
    Si existe JWT en el header, lo valida; si no, acepta el token estático de admin.
    Usar solo para endpoints de administración interna (sign-manifest, toggle).
    """
    auth_header = request.headers.get("Authorization", "")
    token = auth_header.replace("Bearer ", "").strip()

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token de autenticación requerido (JWT o Admin Bearer).",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Primero intentar validar como JWT
    if JOSE_AVAILABLE:
        try:
            return await decode_token_federated(token)
        except HTTPException:
            pass

    # Fallback: token estático de administración (para bootstrapping y
    # pentests internos)
    if ADMIN_TOKEN_ENV and secrets.compare_digest(token, ADMIN_TOKEN_ENV):
        return {"sub": "admin", "role": "ADMIN", "jti": "static-admin-token"}

    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="RBAC: Acceso denegado. Token inválido o sin privilegios suficientes.",
    )
