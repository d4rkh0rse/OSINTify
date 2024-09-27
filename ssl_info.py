import socket
import ssl
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

def ssl_certificate_info(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert_der = ssock.getpeercert(True)
                cert = x509.load_der_x509_certificate(cert_der, default_backend())
                issuer = cert.issuer
                subject = cert.subject
                not_valid_before = cert.not_valid_before_utc
                not_valid_after = cert.not_valid_after_utc
                serial_number = cert.serial_number
                version = cert.version
                public_key = cert.public_key()
                public_key_info = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode('utf-8')
                san_extension = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                san = san_extension.value.get_values_for_type(x509.DNSName)

                cert_info = {
                    'Issuer': issuer.rfc4514_string(),
                    'Subject': subject.rfc4514_string(),
                    'Not Before': not_valid_before,
                    'Not After': not_valid_after,
                    'Serial Number': serial_number,
                    'Version': version,
                    'Public Key': public_key_info,
                    'Subject Alternative Names': san
                }
                return cert_info
    except Exception as e:
        print(f"Error fetching SSL certificate: {e}")
        return {}
