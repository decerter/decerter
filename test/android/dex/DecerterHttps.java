// SPDX-License-Identifier: AGPL-3.0-only

// The Android e2e test client: one HTTPS GET through HttpsURLConnection, which on
// Android is com.android.okhttp over Conscrypt (provider AndroidOpenSSL, BoringSSL of
// the com.android.conscrypt APEX). The test builds it with javac and the SDK's d8
// and runs it under an app UID with app_process:
//   su <uid>,<uid>,3003 app_process -Djava.class.path=<dir>/decerter-https.dex /system/bin DecerterHttps <url> [ca.crt]
// With a CA file the client trusts only that certificate and skips the host name
// check (the eproxy test certificates have no subjectAltName); without it the
// system trust store is used.
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.URL;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManagerFactory;

public class DecerterHttps {
    public static void main(String[] args) throws Exception {
        URL url = new URL(args[0]);
        HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();

        if (args.length > 1) {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            X509Certificate certificate;
            try (InputStream input = new FileInputStream(args[1])) {
                certificate = (X509Certificate) factory.generateCertificate(input);
            }
            KeyStore store = KeyStore.getInstance(KeyStore.getDefaultType());
            store.load(null, null);
            store.setCertificateEntry("ca", certificate);
            TrustManagerFactory trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trust.init(store);
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, trust.getTrustManagers(), null);
            System.out.println("provider " + context.getProvider().getName() + " " + context.getProvider().getClass().getName());
            connection.setSSLSocketFactory(context.getSocketFactory());
            connection.setHostnameVerifier(new HostnameVerifier() {
                public boolean verify(String host, SSLSession session) {
                    return true;
                }
            });
        } else {
            SSLContext context = SSLContext.getDefault();
            System.out.println("provider " + context.getProvider().getName() + " " + context.getProvider().getClass().getName());
        }

        connection.setRequestProperty("Connection", "close");
        int status = connection.getResponseCode();
        System.out.println("status " + status + " cipher " + connection.getCipherSuite());

        ByteArrayOutputStream body = new ByteArrayOutputStream();
        try (InputStream input = status < 400 ? connection.getInputStream() : connection.getErrorStream()) {
            byte[] buffer = new byte[4096];
            int read;
            while (input != null && (read = input.read(buffer)) > 0) {
                body.write(buffer, 0, read);
            }
        }
        String text = body.toString("UTF-8");
        System.out.println("body " + text.substring(0, Math.min(text.length(), 200)).trim());
        connection.disconnect();
    }
}
