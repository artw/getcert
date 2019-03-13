import OpenSSL
from certsrv import Certsrv
import argparse
import jks


def _cli():
    parser = argparse.ArgumentParser(
        description="""
            Generate a key and CSR for specified fqdn(s)
            and request a new certificate from MS CA Web Service.
            First fqdn is used as the common name, additional (if specified) are used as subjectAlt names
            additionally, dumps the latest CA certificate as "<server>.ca.crt"
        """
    )
    parser.add_argument('fqdn', type=str, nargs='+',
                        help="Fully Qualified Domain Names to use for Common Name (and Alt Name(s)) for the certificate"
                        ),
    parser.add_argument("-s", "--server", type=str, required=True,
                        help="the hostname of the server hosting MS CA Web Service"
                        )
    parser.add_argument("-l", "--login", type=str, required=True,
                        help="AD login, that has access to MS CA Web Service"
                        )
    parser.add_argument("-p", "--password", type=str, required=True,
                        help="Password for logon"
                        )
    parser.add_argument("-m", "--method", type=str, default="ntlm", choices=["ntlm", "basic"],
                        help="Auth method",
                        )
    parser.add_argument("-o", "--output", type=str, default="pem", choices=["pem", "jks", "both"],
                        help="Output format, pem - base64 text format, jks - java keystore (default pw = changeit) or both",
                        )
    parser.add_argument("--keystore-pass", type=str, default="changeit",
                        help="Passphrase for new keystore"
                        )
    parser.add_argument("--cafile", type=str,
                        help="Trusted CA certificate for establishing SSL connection"
                        )
    args = parser.parse_args()
    return args


def main():
    # Generate a key
    key = OpenSSL.crypto.PKey()
    key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)

    # Generate a CSR and sign it
    req = OpenSSL.crypto.X509Req()
    req.get_subject().CN = args.fqdn[0]
    san = b"DNS: " + args.fqdn[0].encode()
    if len(args.fqdn) > 1:
        for cn in args.fqdn[1:]:
            san += b", DNS: " + cn.encode()
    san_extension = OpenSSL.crypto.X509Extension(b"subjectAltName", False, san)
    req.add_extensions([san_extension])
    req.set_pubkey(key)
    req.sign(key, "sha256")

    # Get the new cert from the MSCA server
    pem_req = OpenSSL.crypto.dump_certificate_request(OpenSSL.crypto.FILETYPE_PEM, req)
    ca_server = Certsrv(args.server, args.login, args.password, auth_method=args.method, cafile=args.cafile)
    pem_cert = ca_server.get_cert(pem_req, "WebServer")
    pem_key = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, key)

    # Get the latest CA certificate from MSCA
    pem_cacert = ca_server.get_ca_cert()
    # write req, crt and key to files in CWD
    if "pem" in args.output or "both" in args.output:
        req_file = open(args.fqdn[0] + ".req", "w")
        req_file.write(pem_req.decode())
        crt_file = open(args.fqdn[0] + ".crt", "w")
        crt_file.write(pem_cert.decode())
        key_file = open(args.fqdn[0] + ".key", "w")
        key_file.write(pem_key.decode())
        cacrt_file = open(args.server + ".ca.crt", "w")
        cacrt_file.write(pem_cacert.decode())
    # create java keystore
    if "keystore" in args.output or "both" in args.output:
        cert_obj = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, pem_cert)
        dumped_cert = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_obj)

        cacert_obj = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, pem_cacert)
        dumped_cacert = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_ASN1, cacert_obj)

        dumped_key = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_ASN1, key)

        pke = jks.PrivateKeyEntry.new(args.fqdn[0], [dumped_cert], dumped_key, 'rsa_raw')
        pke_ca = jks.TrustedCertEntry.new('CARoot', dumped_cacert)

        keystore = jks.KeyStore.new('jks', [pke_ca, pke])
        keystore.save(args.fqdn[0] + '.jks', args.keystore_pass)

        keystore = jks.KeyStore.new('jks', [pke_ca])
        keystore.save(args.server + '.truststore.jks', args.keystore_pass)


if __name__ == '__main__':
    args = _cli()
    main()
