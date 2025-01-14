import javax.net.ssl.*;
import java.io.*;
import java.net.URL;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;

public class TLSClient {

    public static void main(String[] args) {
        String httpsURL = "https://bnr.ro/Home.aspx";
        String outputFile = "bnr_response.html";

        try {
            // Establish SSL connection
            URL url = new URL(httpsURL);
            HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();

            // Handle SSL certificates
            connection.connect();

            // Check if the certificate matches the expected server
            if (printCertificateDetails(connection)) {
                InputStream inputStream = connection.getInputStream();
                saveResponseToFile(inputStream, outputFile);
                System.out.println("\nHTML content successfully saved to " + outputFile + " file.");
            } else {
                System.out.println("Warning: The certificate does not match the expected server. Content will not be saved.");
            }

        } catch (Exception e) {
            System.out.println("Error connecting to the server: " + e.getMessage());
        }
    }

    private static boolean printCertificateDetails(HttpsURLConnection connection) {
        try {
            System.out.println("--- Certificate Information ---");

            // Get the server's certificates from the connection
            Certificate[] certs = connection.getServerCertificates();

            // Print only the first certificate (the server certificate)
            if (certs.length > 0 && certs[0] instanceof X509Certificate) {
                X509Certificate x509Cert = (X509Certificate) certs[0];

                System.out.println("Version: " + x509Cert.getVersion());
                System.out.println("Serial Number: " + x509Cert.getSerialNumber());
                System.out.println("Issuer: " + x509Cert.getIssuerDN());
                System.out.println("Issued On: " + x509Cert.getNotBefore());
                System.out.println("Valid Until: " + x509Cert.getNotAfter());
                System.out.println("Subject: " + x509Cert.getSubjectDN());
                System.out.println("Signature Algorithm: " + x509Cert.getSigAlgName());
                System.out.println("Public Key: " + x509Cert.getPublicKey().getClass().getSimpleName() + ", "
                        + ((RSAPublicKey) x509Cert.getPublicKey()).getModulus().bitLength() + " bits");

                // Check if the certificate matches the expected values
                if (x509Cert.getSubjectDN().getName().contains("CN=*.bnr.ro")) {
                    return true;
                } else {
                    System.out.println("\nWarning: This is not the real Romanian National Bank server!");
                    return false;
                }
            }

        } catch (Exception e) {
            System.out.println("Error retrieving certificate details: " + e.getMessage());
        }

        return false;
    }

    private static void saveResponseToFile(InputStream inputStream, String outputFile) {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
             BufferedWriter writer = new BufferedWriter(new FileWriter(outputFile))) {

            String line;
            while ((line = reader.readLine()) != null) {
                writer.write(line);
                writer.newLine();
            }
        } catch (IOException e) {
            System.out.println("Error saving response: " + e.getMessage());
        }
    }
}
