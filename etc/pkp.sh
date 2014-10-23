openssl x509 -noout -in rsa-cert.pem -pubkey | openssl asn1parse -noout -inform pem -out public.key
openssl dgst -sha256 -binary public.key | base64
