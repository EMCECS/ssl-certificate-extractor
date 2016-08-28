# SSL Server Certificate Utility
When dealing with SSL servers inside enterprises, you will see a lot of self-signed certificates and internal CAs.
Sometimes it's difficult for users to understand what certificate is required to properly trust the server.  This
utility will connect to the server and analyze the certificate chain presented and identify the root certificate
needed to trust the server.  The root certificate (if found) will then be stored in a file for later use.  If the
root certificate cannot be found, the DN (Distinguished Name) of the certificate will be printed so the user can 
locate the correct root certificate elsewhere (usually an enterprise CA).

The application will also analyze the chain presented from the server and identify any issues it finds in the chain, 
e.g. the chain's certificates are not in the correct order.

Finally, there is also an option to supply a root certificate to validate the chain for situations where Java does not
have the root CA certificate installed by default.

# Usage
In its basic form, you run the JAR and connect to a host:port using the --connect argument, e.g.

```
$ java -jar ssl-certificate-extractor.jar -connect object.ecstestdrive.com:443
Loading Java's root certificates...
Connecting to object.ecstestdrive.com:443
Connected? true
Certificate: 
  Subject: CN=*.object.ecstestdrive.com, OU=Advanced Software Division, O=EMC, L=Bedford, ST=Massachusetts, C=US
  Issuer : CN=thawte SHA256 SSL CA, O="thawte, Inc.", C=US
Certificate: 
  Subject: CN=thawte SHA256 SSL CA, O="thawte, Inc.", C=US
  Issuer : CN=thawte Primary Root CA - G3, OU="(c) 2008 thawte, Inc. - For authorized use only", OU=Certification Services Division, O="thawte, Inc.", C=US
The server sent 2 certificates
The root certificate appears to be CN=thawte Primary Root CA - G3, OU="(c) 2008 thawte, Inc. - For authorized use only", OU=Certification Services Division, O="thawte, Inc.", C=US
  the server didn't send the CA cert (normal), but Java recognizes it as trusted.

Wrote root certificate to root.pem
```

If the root certificate cannot be found in Java's keystore (cacerts), a message will be printed with the proper
certificate name: 

```
$ java -jar ssl-certificate-extractor.jar -connect www.google.com:443 
Loading Java's root certificates...
Connecting to www.google.com:443
Connected? true
Certificate: 
  Subject: CN=www.google.com, O=Google Inc, L=Mountain View, ST=California, C=US
  Issuer : EMAILADDRESS=webfilteradmin@emc.com, CN=EMC SSL Decryption Authority, OU=Global Security Organization, O=EMC Corporation, L=Southborough, ST=Massachusetts, C=US
Certificate: 
  Subject: EMAILADDRESS=webfilteradmin@emc.com, CN=EMC SSL Decryption Authority, OU=Global Security Organization, O=EMC Corporation, L=Southborough, ST=Massachusetts, C=US
  Issuer : CN=EMC SSL Decryption Authority, OU=Global Security Organization, O=EMC Corporation, C=US, EMAILADDRESS=webfilteradmin@emc.com
The server sent 2 certificates
The root certificate appears to be CN=EMC SSL Decryption Authority, OU=Global Security Organization, O=EMC Corporation, C=US, EMAILADDRESS=webfilteradmin@emc.com
  and Java doesn't have this certificate as a trusted certificate.  This may happen if you're not using a common CA (Certificate Authority) or your organization runs its own CA.  Please contact your security administrator and tell them you're looking for the root certificate for CN=EMC SSL Decryption Authority, OU=Global Security Organization, O=EMC Corporation, C=US, EMAILADDRESS=webfilteradmin@emc.com
```

Once you've located the proper root certificate, you can verify it with the --verify option, e.g. 

```
$ java -jar ssl-certificate-extractor.jar -connect www.google.com:443 --verify emcssl.pem 
Loading Java's root certificates...
Loading your certificate from: ../../emcssl.pem
Connecting to www.google.com:443
Connected? true
Certificate: 
  Subject: CN=www.google.com, O=Google Inc, L=Mountain View, ST=California, C=US
  Issuer : EMAILADDRESS=webfilteradmin@emc.com, CN=EMC SSL Decryption Authority, OU=Global Security Organization, O=EMC Corporation, L=Southborough, ST=Massachusetts, C=US
Certificate: 
  Subject: EMAILADDRESS=webfilteradmin@emc.com, CN=EMC SSL Decryption Authority, OU=Global Security Organization, O=EMC Corporation, L=Southborough, ST=Massachusetts, C=US
  Issuer : CN=EMC SSL Decryption Authority, OU=Global Security Organization, O=EMC Corporation, C=US, EMAILADDRESS=webfilteradmin@emc.com
The server sent 2 certificates
The root certificate appears to be CN=EMC SSL Decryption Authority, OU=Global Security Organization, O=EMC Corporation, C=US, EMAILADDRESS=webfilteradmin@emc.com
  and Java doesn't have this certificate as a trusted certificate.  However, the certificate you passed to verify IS the correct root certificate!

Wrote root certificate to root.pem
```
