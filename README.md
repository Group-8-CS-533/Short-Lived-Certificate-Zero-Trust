# Documentation

This documentation provides a step-by-step guide on short-lived authentication using the Zero Trust Model.

## Server B Public Key Infrastructure (PKI)

### Creating Directories Needed for our Certificate Authority

To begin, create the necessary directories for the root Certificate Authority (root CA), intermediate/subordinate CA (sub CA), and ServerA.

**Terminologies**:

- **private**: Used to store the private key
- **certs**: Used to store the certificates
- **newcerts**: Used to store newly issued certificates for clients
- **crl**: Stands for Certificate Revocation List
- **csr**: Stands for Certificate Signing Request

```bash
mkdir -p ca/{root-ca,sub-ca,serverA}/{private,certs,newcerts,crl,csr}
```

Change the permissions of the private directories that hold the private keys of the root CA, sub CA, and ServerA to 700.

```bash
chmod -v 700 ca/{root-ca,sub-ca,serverA}/private
```

Create an index file in the root CA and sub CA directories. The index file serves as a database to store all the certificates generated in the PKI.

```bash
touch ca/{root-ca,sub-ca}/index
```

Generate a random hexadecimal number for the root and sub CA and save it in the serial directory. Each certificate generated is assigned a unique serial number.

```bash
openssl rand -hex 16 > ca/root-ca/serial
```

```bash
openssl rand -hex 16 > ca/sub-ca/serial
```

### Private Key Generation

Change your current directory to the private directory to generate the private keys.

```bash
cd ca
```

#### Creating Root CA Private Key

Generate the private key for the root CA. The **-aes256** flag adds a passphrase to the private key for additional security, making it difficult for unauthorized individuals to use the key without knowing the correct passphrase. The **4096** key size provides stronger encryption.

```bash
openssl genrsa -aes256 -out root-ca/private/ca.key 4096
```

#### Creating Sub CA Private Key

Generate the private key for the intermediate/subordinate CA (sub CA). This key will be used for signing the root CA.

```bash
openssl genrsa -aes256 -out sub-ca/private/sub-ca.key 4096
```

#### Creating ServerA Private Key

Generate the private key for ServerA. No passphrase is added to the server's private key, and the key size is reduced to prevent overloading the server.

```bash
openssl genrsa -out serverA/private/serverA.key 2048
```

#### Creating Configuration Files

Create the configuration files for the root CA (root-ca.conf) and sub CA (sub-ca.conf).

#### Public Key for our CA (Root CA)

Change to the root CA directory.

```bash
cd root-ca/
```

Generate the public key for the root CA using the root-ca.conf configuration file. The key is self-signed, valid for 7500 days, and uses the SHA256 hash algorithm. The resulting certificate is saved as "ca.crt" in the certs directory.

```bash
openssl req -config root-ca.conf -key private/ca.key -new -x509 -days 7500 -sha256 -extensions v3_ca -out certs/ca.crt
```

To view the details of the generated certificate, use the following command:

```bash
openssl x509 -noout -in certs/ca.crt -text
```

#### Creating a Certificate Signing Request for Sub CA

Change to the sub CA directory.

```bash
cd ../sub-ca/
```

Generate a certificate signing request (CSR) for the

 sub CA using the sub-ca.conf configuration file.

```bash
openssl req -config sub-ca.conf -key private/sub-ca.key -sha256 -out csr/sub-ca.csr
```

To sign the sub-CA certificate, return to the root-ca directory.

```bash
openssl ca -config root-ca.conf -extensions v3_intermediate_ca -days 3650 -notext -in ../sub-ca/csr/sub-ca.csr -out ../sub-ca/certs/sub-ca.crt
```

To view the details of the sub-CA certificate, use the following command:

```bash
openssl x509 -noout -in ../sub-ca/certs/sub-ca.crt -text
```

Show the structure of the certificates created using the **tree** command.

### Generating ServerA Certificate

**Note:**

- Configuration files are not required for creating the server certificate.
- Keep the certificate signing request (CSR) file local to the server for reuse when requesting a new certificate.

#### Generating Certificate Signing Request (CSR)

Change to the serverA directory.

```bash
cd ../serverA
```

Generate a certificate signing request (CSR) for ServerA.

```bash
openssl req -key private/serverA.key -new -sha256 -out csr/serverA.csr
```

You will be prompted to provide the required information. Ensure that the common name matches the fully qualified domain name (FQDN) used by clients to access the server. The server certificate request is now generated. The next step is to sign the server CSR using the signing authority, which is the intermediate CA (sub CA).

```bash
cd ../sub-ca
openssl ca -config sub-ca.conf -extensions server_certs -days 0 -seconds 300 -notext -in ../serverA/csr/serverA.csr -out ../serverA/certs/serverA.crt
```

To view the database of all certificates, use the following command:

```bash
cat index
```

To view the newly created server certificate, use the following command:

```bash
ls newcerts
```

To test the certificate on ServerA, which hosts the Nginx web server, concatenate the server certificate (serverA.crt) and the sub-ca.crt into a file named chained.crt. This file will be used in the ssl_certificate section.

```bash
cat serverA.crt ../../sub-ca/certs/sub-ca.crt > chained.crt
```

### Testing the Certificate

The hostname on the certificate must match the configured certificate.

```bash
echo "127.0.0.2 www.trustzerd.com" >> /etc/hosts
ping www.trustzerd.com
```

#### Different Testing Methods

##### Testing with OpenSSL

Open two terminal windows. In the **first window**, start the server.

```bash
openssl s_server -accept 443 -www -key private/server.key -cert certs/server.crt -CAfile ../sub-ca/certs/sub-ca.crt
```

In the **second window**, run the following command to test the server using cURL:

```bash
curl https://trustzedo.com
```

Since the operating system does not trust the root CA, the connection will fail.

To trust the root CA, copy the ca.crt file to the appropriate directory. The exact directory location depends on the operating system. In this example, we assume the directory is `/etc/pki/trust/anchors/`.

```bash
cp ca/root-ca/certs/ca.crt /etc/pki/trust/anchors/
```

Update the certificate database:

```bash
sudo update-ca-trust
```

Rerun the cURL command to test the connection:

```bash
curl https://trustzedo.com
```

##### Configuring

 Nginx

Edit the Nginx configuration file:

```bash
nano /etc/nginx/nginx.conf
```

Scroll down to the http section and uncomment the following lines:

```nginx
server_name www.trustzedo.com;
ssl_certificate /root/ca/server/certs/chained.crt;
ssl_certificate_key /root/ca/server/private/server.key;
```

Save the changes and restart the Nginx web server:

```bash
echo hello > /srv/www/htdocs/index.html
curl https://www.example.com
```

Congratulations! You have successfully tested the certificate and configured Nginx to use it.