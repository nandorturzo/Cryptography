import javax.net.ssl.*;
import java.io.*;
import java.net.URL;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

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
            printCertificateDetails(connection);

            // Perform HTTP GET request
            InputStream inputStream = connection.getInputStream();
            saveResponseToFile(inputStream, outputFile);
            System.out.println("HTML content successfully saved to " + outputFile + " file.");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void printCertificateDetails(HttpsURLConnection connection) {
        try {
            System.out.println("--- Certificate Information ---");

            Certificate[] certs = connection.getServerCertificates();
            for (Certificate cert : certs) {
                if (cert instanceof X509Certificate) {
                    X509Certificate x509Cert = (X509Certificate) cert;

                    System.out.println("Version: " + x509Cert.getVersion());
                    System.out.println("Serial Number: " + x509Cert.getSerialNumber());
                    System.out.println("Issuer: " + x509Cert.getIssuerDN());
                    System.out.println("Issued On: " + x509Cert.getNotBefore());
                    System.out.println("Valid Until: " + x509Cert.getNotAfter());
                    System.out.println("Subject: " + x509Cert.getSubjectDN());
                    System.out.println("Signature Algorithm: " + x509Cert.getSigAlgName());
                    System.out.println("Public Key: " + x509Cert.getPublicKey());
                }
            }

        } catch (Exception e) {
            System.out.println("Error retrieving certificate details: " + e.getMessage());
        }
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
