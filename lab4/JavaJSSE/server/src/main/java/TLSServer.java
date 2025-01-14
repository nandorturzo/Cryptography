import com.sun.net.httpserver.*;
import javax.net.ssl.*;
import java.io.*;
import java.net.InetSocketAddress;
import java.security.KeyStore;

public class TLSServer {

    public static void main(String[] args) throws Exception {
        // Loading HTML
        String htmlFile = "bnr_response.html";
        String htmlContent = new String(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(htmlFile)));

        // Setuping SSL connection
        char[] password = "password".toCharArray(); // Keystore password
        KeyStore keyStore = KeyStore.getInstance("JKS");
        try (FileInputStream fis = new FileInputStream("ServerCA\\server.keystore")) {
            keyStore.load(fis, password);
        }

        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(keyStore, password);

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), null, null);

        // 3. Inicializaing Server
        HttpsServer server = HttpsServer.create(new InetSocketAddress(443), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(sslContext) {
            public void configure(HttpsParameters params) {
                try {
                    SSLContext c = getSSLContext();
                    SSLEngine engine = c.createSSLEngine();
                    params.setNeedClientAuth(false);
                    params.setCipherSuites(engine.getEnabledCipherSuites());
                    params.setProtocols(engine.getEnabledProtocols());
                    params.setSSLParameters(c.getDefaultSSLParameters());
                } catch (Exception ex) {
                    System.err.println("Failed to create HTTPS port");
                }
            }
        });

        // 4. HTTP GET handler
        server.createContext("/", exchange -> {
            if ("GET".equals(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(200, htmlContent.getBytes().length);
                OutputStream os = exchange.getResponseBody();
                os.write(htmlContent.getBytes());
                os.close();
            } else {
                exchange.sendResponseHeaders(405, -1); // Method Not Allowed
            }
        });

        server.setExecutor(null); // Default executor
        server.start();
        System.out.println("TLS server started on port 443");
    }
}