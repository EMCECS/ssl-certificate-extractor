import org.apache.commons.cli.*;

import javax.net.ssl.*;
import java.io.*;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.*;
import java.util.Base64;
import java.util.Set;

/**
 * Class to connect to a SSL socket and analyze the certificate chain presented.  If possible, the root certificate
 * of the chain will be extracted and saved to a PEM-encoded x.509 certificate file.  Optionally, a root certificate
 * file may be specified and the SSL certificate chain will be verified against that root certificate (used to test
 * that you have the correct root certificate).
 */
public class SSLCertificateExtractor {

    public static final int EXIT_OK = 0;
    public static final int EXIT_CONNECT_FAILURE = 1;
    public static final int EXIT_SSL_ERROR = 2;
    public static final int EXIT_CERT_MISMATCH = 3;
    public static final int EXIT_ARG_ERROR = 4;
    public static final int EXIT_NO_ROOT_CERT_FOUND = 5;
    public static final int EXIT_VERIFY_CERT_NO_EXIST = 6;
    public static final int EXIT_VERIFY_CERT_LOAD_ERROR = 7;
    public static final int EXIT_WRITE_ROOT_CERT_ERROR = 8;
    public static final int EXIT_SERVER_CHAIN_ERROR = 9;

    public static final String BEGIN_CERT = "-----BEGIN CERTIFICATE-----";
    public static final String END_CERT = "-----END CERTIFICATE-----";

    public static final String ARG_SILENT = "silent";
    public static final String ARG_CONNECT = "connect";
    public static final String ARG_VERIFY = "verify-root";

    public static void main(String[] args) {
        Options opts = new Options();

        opts.addOption(Option.builder().longOpt(ARG_SILENT).desc("Do not output any text to the terminal").build());
        opts.addOption(Option.builder().longOpt(ARG_CONNECT).hasArg().argName("host:port").required()
                .desc("The host:port to connect to and verify").build());
        opts.addOption(Option.builder().longOpt(ARG_VERIFY).hasArg().argName("path")
                .desc("If specified, verify the given certificate is a valid root to trust the server").build());

        CommandLineParser parser = new DefaultParser();
        try {
            CommandLine line = parser.parse(opts, args);

            SSLCertificateExtractor extractor = new SSLCertificateExtractor(line.getOptionValue(ARG_CONNECT));

            if(line.hasOption(ARG_SILENT)) {
                extractor.setSilent(true);
            }

            if(line.hasOption(ARG_VERIFY)) {
                extractor.setVerifyCert(line.getOptionValue(ARG_VERIFY));
            }

            extractor.run();
        } catch (ParseException e) {
            System.err.println("Error: " + e.getMessage());
            HelpFormatter hf = new HelpFormatter();
            hf.printHelp("java -jar ssl-certificate-extractor.jar", opts);
            System.exit(EXIT_ARG_ERROR);
        }

        System.exit(EXIT_OK);
    }


    private String connect;
    private String verifyCert;
    private boolean silent = false;
    private Principal lastIssuer;
    private Principal lastSubject;
    private X509Certificate lastCert;
    private X509Certificate rootCert;
    private X509Certificate certToVerify;
    private int certsSent;

    public SSLCertificateExtractor(String connect) {
        this.connect = connect;
    }

    public void run() {
        String[] parts = connect.split(":");
        if(parts.length != 2) {
            printMessage("ERROR: connect string must be in the form of host:port");
            System.exit(EXIT_ARG_ERROR);
        }
        String host = parts[0];
        int port = Integer.parseInt(parts[1]);

        try {
            SSLContext ctx = null;
            ctx = SSLContext.getInstance("TLS");
            ctx.init(null, new TrustManager[]{ new CustomTrustManager()}, null);

            printMessage("Loading Java's root certificates...");
            Set<TrustAnchor> anchors = getTrustAnchors();
            if(verifyCert != null) {
                printMessage("Loading your certificate from: " + verifyCert);
                File f = new File(verifyCert);
                if(!f.exists()) {
                    printMessage("ERROR: the file does not exist: " + verifyCert);
                    System.exit(EXIT_VERIFY_CERT_NO_EXIST);
                }
                try(InputStream in = new FileInputStream(f)) {
                    CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
                    certToVerify = (X509Certificate) certificateFactory.generateCertificate(in);
                    in.close();
                } catch (Exception e) {
                    printMessage("ERROR: could not load certificate: " + e);
                    System.exit(EXIT_VERIFY_CERT_LOAD_ERROR);
                }
            }

            printMessage("Connecting to " + connect);
            Socket s = ctx.getSocketFactory().createSocket(host, port);
            printMessage("Connected? " + s.isConnected());
            OutputStream os = s.getOutputStream();
            os.write("GET / HTTP/1.1\n\n".getBytes());
            os.close();
            s.close();

            printMessage(String.format("The server sent %d certificates", certsSent));

            printMessage("The root certificate appears to be " + lastIssuer.getName());

            if(lastIssuer.equals(lastSubject)) {
                // The last certificate was self-signed.  This could either be a single self-signed cert or the root
                // cert (root CA certs are always self-signed since they're the trust anchor).
                if(certsSent == 1) {
                    printMessage("It appears this server is using a self-signed certificate");
                    rootCert = lastCert;
                    X509Certificate anchor = findAnchor(anchors, lastIssuer);
                    printMessage(String.format("NOTE: When using self-signed certificates, the application will need " +
                                "to trust this certificate.  The Java VM running this program %s trust it.",
                            anchor == null?"DOES NOT":"DOES"));
                } else {
                    printMessage("It appears that the server did send us the root certificate (not typical)");
                    rootCert = lastCert;
                    X509Certificate anchor = findAnchor(anchors, lastIssuer);
                    if(anchor == null) {
                        printMessage("NOTE: your server sent the root CA cert during SSL negotiation.  However, " +
                                "this Java VM does not recognize it as trusted.  You'll need to make sure that any " +
                                "application environments install this certificate as a trusted certificate.");
                    } else {
                        // Java also has the cert... use Java's version since we trust that more.
                        rootCert = anchor;
                    }
                }
            } else {
                // Server didn't send the root CA cert.  See if Java recognizes it.
                X509Certificate anchor = findAnchor(anchors, lastIssuer);
                if(anchor == null) {
                    // Java doesn't have it... did the user give us a cert to test?
                    if(verifyCert != null) {
                        if(certToVerify.getSubjectDN().equals(lastIssuer)) {
                            printMessage("  and Java doesn't have this certificate as a trusted certificate.  " +
                                    "However, the certificate you passed to verify IS the correct root certificate!");
                            rootCert = certToVerify;
                        } else {
                            printMessage("ERROR: Java doesn't have this certificate as a trusted certificate AND " +
                                    "the certificate you passed to verify does not appear to match the required " +
                                    "root certificate.");

                            printMessage(String.format("Your certificate: %s\nRequired root: %s",
                                    certToVerify.getSubjectDN(), rootCert.getSubjectDN()));
                            System.exit(EXIT_CERT_MISMATCH);
                        }
                    } else {
                        printMessage("  and Java doesn't have this certificate as a trusted certificate.  This may " +
                                "happen if you're not using a common CA (Certificate Authority) or your " +
                                "organization runs its own CA.  Please contact your security administrator and " +
                                "tell them you're looking for the root certificate for " + lastIssuer);
                        System.exit(EXIT_NO_ROOT_CERT_FOUND);
                    }
                } else {
                    printMessage("  the server didn't send the CA cert (normal), but Java recognizes it as trusted.");
                    rootCert = anchor;
                }
            }

            // write out the root
            try(FileOutputStream out = new FileOutputStream(new File("root.pem"))) {
                Base64.Encoder encoder = Base64.getMimeEncoder(64, new byte[]{0x0a});
                out.write(BEGIN_CERT.getBytes(StandardCharsets.US_ASCII));
                out.write(0x0a);  // Newline
                out.write(encoder.encode(rootCert.getEncoded()));
                out.write(0x0a);  // Newline
                out.write(END_CERT.getBytes(StandardCharsets.US_ASCII));
                out.write(0x0a);  // Newline
                printMessage("\nWrote root certificate to root.pem");
            } catch (Exception e) {
                printMessage("ERROR: could not write root.pem: " + e);
                System.exit(EXIT_WRITE_ROOT_CERT_ERROR);
            }
        } catch (NoSuchAlgorithmException e) {
            printMessage("ERROR: SSL Error: " + e);
            System.exit(EXIT_SSL_ERROR);
        } catch (UnknownHostException e) {
            printMessage("ERROR: Failed to lookup host: " + host);
            System.exit(EXIT_CONNECT_FAILURE);
        } catch (IOException e) {
            printMessage("ERROR: IO Failure: " + e);
            System.exit(EXIT_CONNECT_FAILURE);
        } catch (KeyManagementException e) {
            printMessage("ERROR: SSL Error: " + e);
            System.exit(EXIT_SSL_ERROR);
        } catch (CertificateException e) {
            printMessage("ERROR: SSL Error: " + e);
            System.exit(EXIT_SSL_ERROR);
        } catch (KeyStoreException e) {
            printMessage("ERROR: SSL Error: " + e);
            System.exit(EXIT_SSL_ERROR);
        } catch (InvalidAlgorithmParameterException e) {
            printMessage("ERROR: SSL Error: " + e);
            System.exit(EXIT_SSL_ERROR);
        }
    }

    private X509Certificate findAnchor(Set<TrustAnchor> anchors, Principal certName) {
        for (TrustAnchor anchor :
                anchors) {
            if(anchor.getTrustedCert().getSubjectDN().equals(certName)) {
                return anchor.getTrustedCert();
            }
        }
        return null;
    }

    private void printMessage(String s) {
        if(!silent) {
            System.out.println(s);
        }
    }

    public boolean isSilent() {
        return silent;
    }

    public void setSilent(boolean silent) {
        this.silent = silent;
    }


    public String getConnect() {
        return connect;
    }

    public void setConnect(String connect) {
        this.connect = connect;
    }

    public String getVerifyCert() {
        return verifyCert;
    }

    public void setVerifyCert(String verifyCert) {
        this.verifyCert = verifyCert;
    }

    private Set<TrustAnchor> getTrustAnchors() throws IOException, KeyStoreException, CertificateException,
            NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        // Load the JDK's cacerts keystore file
        String filename = System.getProperty("java.home") + "/lib/security/cacerts".replace('/', File.separatorChar);
        FileInputStream is = new FileInputStream(filename);
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        String password = "changeit";
        keystore.load(is, password.toCharArray());

        // This class retrieves the trust anchor (root) CAs from the keystore
        PKIXParameters params = new PKIXParameters(keystore);
        return params.getTrustAnchors();
    }


    class CustomTrustManager implements X509TrustManager {

        @Override
        public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
        }

        @Override
        public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
            certsSent = x509Certificates.length;
            boolean badChain = false;
            for(X509Certificate cert : x509Certificates) {
                printMessage("Certificate: ");
                printMessage("  Subject: " + cert.getSubjectDN());
                printMessage("  Issuer : " + cert.getIssuerDN());

                // Check to make sure chain is okay
                if(lastIssuer != null && !cert.getSubjectDN().equals(lastIssuer)) {
                    printMessage("ERROR: the certificate chain returned from the server looks incorrect.  The previous certificate's issuer does not match this certificate's subject!");
                    printMessage(String.format("  expected: %s\n  but found: %s", lastIssuer, cert.getSubjectDN()));
                    badChain = true;
                }

                lastCert = cert;
                lastIssuer = cert.getIssuerDN();
                lastSubject = cert.getSubjectDN();
            }

            if(badChain) {
                printMessage("Please fix the server's certificate chain and try again.");
                System.exit(EXIT_SERVER_CHAIN_ERROR);
            }
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }

}
