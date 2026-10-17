"""
cert_gen.py — Self-signed CA and server certificate generation.

Used exclusively by the Track C integration tests.  Produces a temporary
CA key/cert pair and a server key/cert pair signed by that CA, all in a
caller-supplied directory.  Nothing here is imported at production runtime.
"""
import datetime
import ipaddress
import pathlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _rsa_key() -> rsa.RSAPrivateKey:
    """Generate a fresh 2048-bit RSA key."""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )


def _write_key(key: rsa.RSAPrivateKey, path: pathlib.Path) -> None:
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )


def _write_cert(cert: x509.Certificate, path: pathlib.Path) -> None:
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_test_certs(
    dest_dir: pathlib.Path,
    server_hostname: str = "localhost",
    server_ip: str = "127.0.0.1",
) -> dict:
    """
    Generate a self-signed CA and a server certificate signed by it.

    Returns a dict with keys:
        ca_cert_path   — path to CA certificate PEM
        server_cert_path — path to server certificate PEM
        server_key_path  — path to server private key PEM

    The server certificate has:
        - CN = server_hostname
        - SAN DNS = server_hostname
        - SAN IP  = server_ip

    The caller is responsible for configuring the TLS client to trust
    ca_cert_path and the TLS server to use server_cert_path + server_key_path.
    """
    dest_dir = pathlib.Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)

    now = datetime.datetime.now(datetime.timezone.utc)
    one_day = datetime.timedelta(days=1)

    # --- CA key + self-signed certificate ---
    ca_key = _rsa_key()
    ca_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "ScamShield Test CA"),
    ])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - one_day)
        .not_valid_after(now + one_day)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    # --- Server key + CA-signed certificate ---
    srv_key = _rsa_key()
    srv_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, server_hostname),
    ])
    san = x509.SubjectAlternativeName([
        x509.DNSName(server_hostname),
        x509.IPAddress(ipaddress.ip_address(server_ip)),
    ])
    srv_cert = (
        x509.CertificateBuilder()
        .subject_name(srv_name)
        .issuer_name(ca_name)
        .public_key(srv_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - one_day)
        .not_valid_after(now + one_day)
        .add_extension(san, critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    ca_cert_path = dest_dir / "ca_cert.pem"
    srv_cert_path = dest_dir / "server_cert.pem"
    srv_key_path = dest_dir / "server_key.pem"

    _write_cert(ca_cert, ca_cert_path)
    _write_cert(srv_cert, srv_cert_path)
    _write_key(srv_key, srv_key_path)

    return {
        "ca_cert_path": ca_cert_path,
        "server_cert_path": srv_cert_path,
        "server_key_path": srv_key_path,
    }
