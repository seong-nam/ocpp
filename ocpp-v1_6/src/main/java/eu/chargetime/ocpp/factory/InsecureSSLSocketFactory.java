package eu.chargetime.ocpp.factory;

import javax.net.ssl.*;
import java.io.IOException;
import java.net.Socket;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

public class InsecureSSLSocketFactory extends SSLSocketFactory {
    private final SSLSocketFactory delegate;

    public InsecureSSLSocketFactory() throws Exception {
        TrustManager[] trustAll = new TrustManager[]{
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) {}
                    public void checkServerTrusted(X509Certificate[] certs, String authType) {}
                }
        };
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, trustAll, new SecureRandom());
        this.delegate = ctx.getSocketFactory();
    }

    @Override
    public String[] getDefaultCipherSuites() { return delegate.getDefaultCipherSuites(); }

    @Override
    public String[] getSupportedCipherSuites() { return delegate.getSupportedCipherSuites(); }

    private Socket configure(Socket s) {
        if (s instanceof SSLSocket) {
            SSLSocket ssl = (SSLSocket) s;
            SSLParameters params = ssl.getSSLParameters();
            // 호스트네임 검증 끄기
            params.setEndpointIdentificationAlgorithm(null);
            ssl.setSSLParameters(params);
        }
        return s;
    }

    @Override
    public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws java.io.IOException {
        SSLSocket ssl = (SSLSocket) configure(delegate.createSocket(s, host, port, autoClose));
        SSLParameters params = ssl.getSSLParameters();
        params.setEndpointIdentificationAlgorithm(null); // CN/SAN 검증 끄기
        ssl.setSSLParameters(params);
        return ssl;
    }

    @Override
    public Socket createSocket(String host, int port) throws java.io.IOException {
        SSLSocket ssl = (SSLSocket) configure(delegate.createSocket(host, port));
        SSLParameters params = ssl.getSSLParameters();
        params.setEndpointIdentificationAlgorithm(null); // CN/SAN 검증 끄기
        ssl.setSSLParameters(params);
        return ssl;
    }

    @Override
    public Socket createSocket(String host, int port, java.net.InetAddress localHost, int localPort) throws java.io.IOException {
        return configure(delegate.createSocket(host, port, localHost, localPort));
    }

    @Override
    public Socket createSocket(java.net.InetAddress host, int port) throws java.io.IOException {
        return configure(delegate.createSocket(host, port));
    }

    @Override
    public Socket createSocket(java.net.InetAddress address, int port, java.net.InetAddress localAddress, int localPort) throws java.io.IOException {
        return configure(delegate.createSocket(address, port, localAddress, localPort));
    }
}
