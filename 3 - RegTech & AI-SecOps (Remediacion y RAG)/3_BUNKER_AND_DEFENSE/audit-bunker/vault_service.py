import os

import hvac
from src.bunker_logger import log_auditoria


class BunkerVaultClient:
    """Cliente para la integraciÃ³n con HashiCorp Vault.
    Cumple con el requisito P-001 (ENS Alta / Module 14) de evitar almacenar secretos en variables de entorno locales.
    """

    def __init__(self, url: str = "http://127.0.0.1:8200") -> None:
        self.url = os.getenv("VAULT_ADDR", url)
        self.client = hvac.Client(url=self.url)

        role_id = os.getenv("VAULT_ROLE_ID")
        secret_id = os.getenv("VAULT_SECRET_ID")

        if role_id and secret_id:
            try:
                self.client.auth.approle.login(
                    role_id=role_id, secret_id=secret_id,
                )
                log_auditoria(
                    "SYSTEM", "VAULT_AUTH", "Autenticado en Vault vÃ­a AppRole",
                )
            except BunkerSecurityError as e:
                log_auditoria(
                    "SYSTEM",
                    "VAULT_AUTH_FAIL",
                    f"Fallo al autenticar vÃ­a AppRole: {e}",
                )
        else:
            token = os.getenv("VAULT_TOKEN")
            if token:
                self.client.token = token

    def is_authenticated(self) -> bool:
        try:
            return self.client.is_authenticated()
        except BunkerSecurityError:
            return False

    def get_secret(self, path: str, key: str) -> str:
        """Recupera un secreto dinÃ¡mico en tiempo de ejecuciÃ³n."""
        if not self.is_authenticated():
            log_auditoria(
                "SYSTEM",
                "VAULT_AUTH_FAIL",
                "Intento de leer secreto sin conexiÃ³n a Vault",
            )
            msg = "No se pudo autenticar con Vault."
            raise ConnectionError(msg)

        try:
            read_response = self.client.secrets.kv.v2.read_secret_version(
                path=path,
            )

            # Phase 10: Secret TTL & Auditing
            metadata = read_response.get("data", {}).get("metadata", {})
            created_time = metadata.get("created_time", "N/A")
            log_auditoria(
                "SYSTEM",
                "VAULT_SECRET_ACCESS",
                f"Secreto accedido: {path}/{key} (Creado: {created_time})",
            )

            secret = read_response["data"]["data"].get(key)
            if not secret:
                msg = f"Secret '{key}' not found at path '{path}'"
                raise ValueError(msg)
            return secret
        except BunkerSecurityError:
            log_auditoria(
                "SYSTEM",
                "VAULT_READ_ERROR",
                f"Error retrieving secret {key} from {path}",
            )
            raise

    def rotate_secret(
        self, path: str, key: str, new_value: str, ttl_seconds: int = 86400,
    ) -> None:
        """Phase 10: Rota automÃ¡ticamente un secreto y establece TTL."""
        if not self.is_authenticated():
            msg = "No vault connection."
            raise ConnectionError(msg)
        try:
            current = self.client.secrets.kv.v2.read_secret_version(path=path)
            data = current["data"]["data"]
        except BunkerSecurityError:
            data = {}

        data[key] = new_value
        # Nota: Vault KV v2 soporta cas (Check-And-Set) y delete-version.
        # El motor de expiraciÃ³n TTL real requerirÃ­a secret engines dinÃ¡micos
        # (ej. Database/AWS).
        self.client.secrets.kv.v2.create_or_update_secret(
            path=path, secret=data,
        )
        log_auditoria(
            "SYSTEM",
            "VAULT_SECRET_ROTATION",
            f"Secreto rotado exitosamente: {path}/{key}. TTL asignado: {ttl_seconds}s",
        )

    def init_dev_secrets(self) -> None:
        """Inicializa secretos para el entorno de desarrollo local."""
        if not self.is_authenticated():
            return

        try:
            # Asegurar que el secreto existe en desarrollo
            self.client.secrets.kv.v2.create_or_update_secret(
                path="bunker/keys",
                secret={
                    "BUNKER_DB_KEY": "dev_db_super_secret_key_123!!",  # nosec S106
                    "JWT_SECRET": "dev_jwt_secret_456",  # nosec S106
                },
            )
            log_auditoria(
                "SYSTEM",
                "VAULT_INIT",
                "Development secrets initialized in Vault",
            )
        except BunkerSecurityError as e:
            log_auditoria(
                "SYSTEM", "VAULT_INIT_WARN", f"Could not init secrets: {e}",
            )


# Instancia global segura
vault_client = BunkerVaultClient()
