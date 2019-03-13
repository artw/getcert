# getcert

A simple utility based on magnuswatn's _certsrv_ python library to generate a key and sign it using 
Microsoft Certification Authority web service.

- generates a key
- makes a CSR and signs it using the above key
- requests a certificate from MSCA
- writes the csr, key and crt in pem format
- writes the latest MSCA root key to .ca.crt in pem format
- (optionaly) generates a keystore and truststore with the new certificate

Tested only with python 3.7
 
##examples
To use local python
```bash
# pip install certsrv pyOpenSSL requests_ntlm pyjks
# python ./certsrv.py --help

```

To use docker
```bash
# ./build.sh
# ./gencert --help
```

The `gencert` script  mounts `./data` as `/data`, so you can put your CA certificate file in `./data/root.cer`
and specify `--cafile /data/root.cer` as an argument


