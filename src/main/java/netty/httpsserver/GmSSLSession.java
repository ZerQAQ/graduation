package netty.httpsserver;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;
import java.security.Principal;
import java.security.cert.Certificate;

public class GmSSLSession implements SSLSession {
    @Override
    public byte[] getId() {
        System.out.println("[call]session.getId");
        return new byte[0];
    }

    @Override
    public SSLSessionContext getSessionContext() {
        System.out.println("[call]session.getSessionContext");
        return null;
    }

    @Override
    public long getCreationTime() {
        System.out.println("[call]session.getCreationTime");
        return 0;
    }

    @Override
    public long getLastAccessedTime() {
        System.out.println("[call]session.getLastAccessedTime");
        return 0;
    }

    @Override
    public void invalidate() {
        System.out.println("[call]session.invalidate");
    }

    @Override
    public boolean isValid() {
        System.out.println("[call]session.isValid");
        return false;
    }

    @Override
    public void putValue(String s, Object o) {
        System.out.println("[call]session.putValue");
    }

    @Override
    public Object getValue(String s) {
        System.out.println("[call]session.getValue");
        return null;
    }

    @Override
    public void removeValue(String s) {
        System.out.println("[call]session.removeValue");

    }

    @Override
    public String[] getValueNames() {
        System.out.println("[call]session.getValueNames");
        return new String[0];
    }

    @Override
    public Certificate[] getPeerCertificates() throws SSLPeerUnverifiedException {
        System.out.println("[call]session.getPeerCertific");
        return new Certificate[0];
    }

    @Override
    public Certificate[] getLocalCertificates() {
        System.out.println("[call]session.getLocalCertificates");
        return new Certificate[0];
    }

    @Override
    public Principal getPeerPrincipal() throws SSLPeerUnverifiedException {
        System.out.println("[call]session.getPeerPrincipal");
        return null;
    }

    @Override
    public Principal getLocalPrincipal() {
        System.out.println("[call]session.getLocalPrincipal");
        return null;
    }

    @Override
    public String getCipherSuite() {
        System.out.println("[call]session.getCipherSuite");
        return null;
    }

    @Override
    public String getProtocol() {
        System.out.println("[call]session.getProtocol");
        return null;
    }

    @Override
    public String getPeerHost() {
        System.out.println("[call]session.getPeerHost");
        return null;
    }

    @Override
    public int getPeerPort() {
        System.out.println("[call]session.getPeerPort");
        return 0;
    }

    @Override
    public int getPacketBufferSize() {
        System.out.println("[call]session.getPacketBufferSize");
        return (1 << 16) + 4;
    }

    @Override
    public int getApplicationBufferSize() {
        System.out.println("[call]session.getApplicationBufferSize");
        return (1 << 15);
    }
}
