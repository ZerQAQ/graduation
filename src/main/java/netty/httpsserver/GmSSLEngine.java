package netty.httpsserver;

import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;

import static netty.httpsserver.GmSSLEngine.GMSSLHandshakeStatus.*;

public class GmSSLEngine extends SSLEngine {

    public static enum GMSSLHandshakeStatus {
        WAIT_CLIENT_HELLO,
        PREPARE_SERVER_HELLO,
        PREPARE_CERTIFICATE,
        PREPARE_SERVER_KEY_EXCHANGE,
        PREPARE_SERVER_HELLO_DONE,
        WAIT_CLIENT_KEY_EXCHANGE,
        WAIT_CHANGE_CIPHER_SPEC,
        PREPARE_CHANGE_CIPHER_SPEC,
        OK;
    }

    private final SM2Util SM2UtilInstance;

    private GMSSLHandshakeStatus handshakeStatus;
    private PacketParser.ClientHello clientHello;
    private PacketParser.Certificate certificate;
    private PacketParser.ClientKeyExchange clientKeyExchange;

    private final String[] CertFilesPath;

    private int sequenceNumber;

    private final ByteBuffer in;
    private byte[] preMasterKey;

    public GmSSLEngine(String[] CertFilesPath, String privateKeyPath) throws GeneralSecurityException, IOException {
        SM2UtilInstance = new SM2Util();
        SM2UtilInstance.loadPrivateKey(privateKeyPath);

        handshakeStatus = WAIT_CLIENT_HELLO;
        this.CertFilesPath = CertFilesPath;
        sequenceNumber = 0;

        int BUFFER_SIZE = (1 << 17) + 5;
        this.in = ByteBuffer.allocate(BUFFER_SIZE);
    }

    private static void HMacWithSM3(HMac hMac, byte[] seed, byte[] dst){
        hMac.update(seed, 0, seed.length);
        hMac.doFinal(dst, 0);
        hMac.reset();
    }

    private static void PRF(byte[] secret, byte[] label, byte[] seed, byte[] dst){
        byte[] realSeed = new byte[label.length + seed.length];
        System.arraycopy(label, 0, realSeed, 0, label.length);
        System.arraycopy(seed, 0, realSeed, label.length, seed.length);

        HMac hMac = new HMac(new SM3Digest());
        hMac.init(new KeyParameter(secret));

        final int HASH_SIZE = 32;
        byte[] A = new byte[HASH_SIZE], msg = new byte[HASH_SIZE + realSeed.length], temp = new byte[HASH_SIZE];
        HMacWithSM3(hMac, realSeed, A);
        System.arraycopy(realSeed, 0, msg, HASH_SIZE, realSeed.length);

        int index = 0, length = dst.length;
        while(index < length){
            System.arraycopy(A, 0, msg, 0, HASH_SIZE);
            HMacWithSM3(hMac, msg, temp);
            System.arraycopy(temp, 0, dst, index, Math.min(HASH_SIZE, length - index));
            HMacWithSM3(hMac, A, A);
            index += HASH_SIZE;
        }
    }

    @Override
    public SSLEngineResult wrap(ByteBuffer [] srcs, int offset,
                                int length, ByteBuffer dst) throws SSLException {
        System.out.println("[call]wrap");
        System.out.println("[wrap]" + handshakeStatus);
        final int byteProduced;
        switch(handshakeStatus){
            case PREPARE_SERVER_HELLO:
                PacketParser.ServerHello serverHello = new PacketParser.ServerHello();
                SecureRandom random = new SecureRandom();
                serverHello.random = new byte[32];
                random.nextBytes(serverHello.random);
                serverHello.sessionLength = 32;
                serverHello.sessionId = new byte[32];
                random.nextBytes(serverHello.sessionId);

                serverHello.cipherSuite = -1;
                for (int cipherSuite : clientHello.cipherSuites){
                    if(cipherSuite == PacketParser.CipherSuite.ECC_SM4_SM3){
                        serverHello.cipherSuite = cipherSuite;
                    }
                }
                if(serverHello.cipherSuite == -1){
                    System.out.println("no supported ciphersuite");
                    handshakeStatus = WAIT_CLIENT_HELLO;
                    return new SSLEngineResult(
                            SSLEngineResult.Status.CLOSED,
                            SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING,
                            0, 0, 0
                    );
                }

                serverHello.compressMethod = -1;
                for (int compressMethod : clientHello.compressMethods){
                    if(compressMethod == PacketParser.CompressMethod.NULL){
                        serverHello.compressMethod = compressMethod;
                    }
                }
                if(serverHello.compressMethod == -1){
                    System.out.println("no supported compress method");
                    handshakeStatus = WAIT_CLIENT_HELLO;
                    return new SSLEngineResult(
                            SSLEngineResult.Status.CLOSED,
                            SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING,
                            0, 0, 0
                    );
                }

                byteProduced = serverHello.toByte(dst);

                System.out.println("send server hello");
                handshakeStatus = PREPARE_CERTIFICATE;

                return new SSLEngineResult(
                        SSLEngineResult.Status.OK,
                        SSLEngineResult.HandshakeStatus.NEED_WRAP,
                        0, byteProduced, 0
                );
            case PREPARE_CERTIFICATE:
                certificate = new PacketParser.Certificate();
                try {
                    CertificateFactory factory = CertificateFactory.getInstance("X.509", "BC");
                    for(String filePath : CertFilesPath){
                        try {
                            FileInputStream f = new FileInputStream(filePath);
                            certificate.addCert((X509Certificate) factory.generateCertificate(f));
                        } catch (FileNotFoundException e) {
                            e.printStackTrace();
                        }
                    }
                } catch (CertificateException | NoSuchProviderException e) {
                    e.printStackTrace();
                }

                byteProduced = certificate.toByte(dst);

                System.out.println("send certificate");
                handshakeStatus = PREPARE_SERVER_HELLO_DONE;

                return new SSLEngineResult(
                        SSLEngineResult.Status.OK,
                        SSLEngineResult.HandshakeStatus.NEED_WRAP,
                        0, byteProduced, 0
                );
            case PREPARE_SERVER_HELLO_DONE:
                byteProduced = PacketParser.ServerHelloDone.toByte(dst);
                handshakeStatus = WAIT_CLIENT_KEY_EXCHANGE;
                System.out.println("send server hello done");
                return new SSLEngineResult(
                        SSLEngineResult.Status.OK,
                        SSLEngineResult.HandshakeStatus.NEED_UNWRAP,
                        0, byteProduced, 0
                );
            default:
                return new SSLEngineResult(
                        SSLEngineResult.Status.OK,
                        SSLEngineResult.HandshakeStatus.NEED_UNWRAP,
                        0, 0, 0
                );
        }
    }

    public SSLEngineResult unwarpSingle(ByteBuffer src, ByteBuffer dst)
            throws SSLException, NoSuchPaddingException, IllegalBlockSizeException,
            NoSuchAlgorithmException, InvalidKeySpecException, BadPaddingException, InvalidKeyException {
        switch (handshakeStatus){
            case WAIT_CLIENT_HELLO:
                if (PacketParser.getPacketType(src) == PacketParser.PacketType.HANDSHAKE &&
                        PacketParser.getHandshakeType(src) == PacketParser.HandshakeType.CLIENT_HELLO){
                    System.out.println("accept client hello");
                    clientHello = PacketParser.ClientHello.fromByteBuffer(src);
                    System.out.println(clientHello);
                    handshakeStatus = PREPARE_SERVER_HELLO;
                    return new SSLEngineResult(
                            SSLEngineResult.Status.OK,
                            SSLEngineResult.HandshakeStatus.NEED_WRAP,
                            src.position(), 0, 0
                    );
                }
                System.out.println("[unwarp]unacceptable packet in WAIT_CLIENT_HELLO");
                break;
            case WAIT_CLIENT_KEY_EXCHANGE:
                if (PacketParser.getPacketType(src) == PacketParser.PacketType.HANDSHAKE &&
                        PacketParser.getHandshakeType(src) == PacketParser.HandshakeType.CLIENT_KEY_EXCHANGE){
                    System.out.println("accept client key exchange");
                    clientKeyExchange = PacketParser.ClientKeyExchange.fromByteBuffer(src);
                    handshakeStatus = WAIT_CHANGE_CIPHER_SPEC;

                    System.out.println("payload: " + Formatter.bytesToHex(clientKeyExchange.payload));

                    try {
                        //clientKeyExchange.getEncBytesDebug();
                        preMasterKey = SM2UtilInstance.prvKetDecrypt(
                                clientKeyExchange.getEncBytes()
                        );
                        System.out.println("pre master key:" + Formatter.bytesToHex(preMasterKey));
                    } catch (IOException e) {
                        e.printStackTrace();
                    }

                    return new SSLEngineResult(
                            SSLEngineResult.Status.OK,
                            SSLEngineResult.HandshakeStatus.NEED_WRAP,
                            src.position(), 0, 0
                    );
                }
                break;
            case WAIT_CHANGE_CIPHER_SPEC:
                break;
            default:
                break;
        }
        throw new SSLException("unexpected packet accepted.");
    }

    @Override
    public SSLEngineResult unwrap(ByteBuffer src,
                                  ByteBuffer [] dsts, int offset, int length) throws SSLException {
        System.out.printf("[call]unwrap, src size %d\n", src.remaining());

        in.put(src);
        int index = 0, byteConsume = 0, byteProduced = 0;
        SSLEngineResult returnSSLEngineResult = new SSLEngineResult(
           SSLEngineResult.Status.OK,
           this.handshakeStatus == GMSSLHandshakeStatus.OK? SSLEngineResult.HandshakeStatus.FINISHED:
                   SSLEngineResult.HandshakeStatus.NEED_UNWRAP,
                0, 0, sequenceNumber
        );
        while (PacketParser.getPacketSize(in, 0) + 5 <= in.position() && index < length){
            in.limit(in.position());
            in.position(0);

            try {
                returnSSLEngineResult = unwarpSingle(in, dsts[offset + index]);
            } catch (NoSuchPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException | InvalidKeySpecException | BadPaddingException | InvalidKeyException e) {
                System.out.println("catch exception");
                e.printStackTrace();
                throw new SSLException(e.getMessage(), e);
            }
            byteConsume += returnSSLEngineResult.bytesConsumed();
            byteProduced += returnSSLEngineResult.bytesProduced();

            index ++;
            in.compact();
        }

        System.out.printf("[unwrap] in size : %d, produce %d packet\n", in.position(), index);
        return new SSLEngineResult(
                returnSSLEngineResult.getStatus(),
                returnSSLEngineResult.getHandshakeStatus(),
                byteConsume, byteProduced, sequenceNumber
        );
    }

    @Override
    public Runnable getDelegatedTask() {
        System.out.println("[call]getDelegatedTask");
        return null;
    }

    @Override
    public void closeInbound() throws SSLException {
        System.out.println("[call]closeInbound");
    }

    @Override
    public boolean isInboundDone() {
        System.out.println("[call]isInboundDone");
        return false;
    }

    @Override
    public void closeOutbound() {
        System.out.println("[call]closeOutbound");
    }

    @Override
    public boolean isOutboundDone() {
        System.out.println("[call]isOutboundDone");
        return false;
    }

    @Override
    public String[] getSupportedCipherSuites() {
        System.out.println("[call]getSupportedCipherSuites");
        return new String[0];
    }

    @Override
    public String[] getEnabledCipherSuites() {
        System.out.println("[call]getEnabledCipherSuites");
        return new String[0];
    }

    @Override
    public void setEnabledCipherSuites(String[] strings) {
        System.out.println("[call]setEnabledCipherSuites");
    }

    @Override
    public String[] getSupportedProtocols() {
        System.out.println("[call]getSupportedProtocols");
        return new String[0];
    }

    @Override
    public String[] getEnabledProtocols() {
        System.out.println("[call]getEnabledProtocols");
        return new String[0];
    }

    @Override
    public void setEnabledProtocols(String[] strings) {
        System.out.println("[call]setEnabledProtocols");
    }

    @Override
    public SSLSession getSession() {
        System.out.println("[call]getSession");
        return new GmSSLSession();
    }

    @Override
    public void beginHandshake() throws SSLException {
        System.out.println("[call]Begin handshake");
    }

    @Override
    public SSLEngineResult.HandshakeStatus getHandshakeStatus() {
        System.out.println("[call]Handshake status");
        switch (handshakeStatus) {
            case WAIT_CLIENT_HELLO: case WAIT_CHANGE_CIPHER_SPEC: case WAIT_CLIENT_KEY_EXCHANGE:
                return SSLEngineResult.HandshakeStatus.NEED_UNWRAP;
            case PREPARE_SERVER_HELLO: case PREPARE_CERTIFICATE: case PREPARE_SERVER_KEY_EXCHANGE:
            case PREPARE_CHANGE_CIPHER_SPEC:
                return SSLEngineResult.HandshakeStatus.NEED_WRAP;
            case OK:
                return SSLEngineResult.HandshakeStatus.FINISHED;
            default:
                return SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING;
        }
    }

    @Override
    public void setUseClientMode(boolean b) {
        System.out.println("[call]setUseClientMode");
    }

    @Override
    public boolean getUseClientMode() {
        System.out.println("[call]getUseClientMode");
        return false;
    }

    @Override
    public void setNeedClientAuth(boolean b) {
        System.out.println("[call]setNeedClientAuth");
    }

    @Override
    public boolean getNeedClientAuth() {
        System.out.println("[call]getNeedClientAuth");
        return false;
    }

    @Override
    public void setWantClientAuth(boolean b) {
        System.out.println("[call]setWantClientAuth");
    }

    @Override
    public boolean getWantClientAuth() {
        System.out.println("[call]getWantClientAuth");
        return false;
    }

    @Override
    public void setEnableSessionCreation(boolean b) {
        System.out.println("[call]setEnableSessionCreation");
    }

    @Override
    public boolean getEnableSessionCreation() {
        System.out.println("[call]getEnableSessionCreation");
        return false;
    }
}
