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
import java.io.*;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

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
        WAIT_FINISHED,
        PREPARE_CHANGE_CIPHER_SPEC,
        PREPARE_FINISHED,
        OK;
    }

    // SM3 hash size
    private static final int HASH_SIZE = 32;

    private static final int SM4_KEY_SIZE = 16;

    private final SM2Util SM2UtilInstance;

    private ByteBuffer handshakeMsg;

    private GMSSLHandshakeStatus handshakeStatus;
    private PacketParser.ClientHello clientHello;
    private PacketParser.ServerHello serverHello;
    private PacketParser.Certificate certificate;
    private PacketParser.ClientKeyExchange clientKeyExchange;
    private PacketParser.Finished clientFinished, serverFinished;

    private final String[] CertFilesPath;

    private long sequenceNumber, acknowledgeNumber;

    private final ByteBuffer in;
    private byte[] preMasterSecret, masterSecret;
    private byte[] clientWriteMACSecret, serverWriteMACSecret;
    private byte[] clientWriteKey, serverWriteKey;

    public GmSSLEngine(String[] CertFilesPath, String privateKeyPath) throws GeneralSecurityException, IOException {
        SM2UtilInstance = new SM2Util();
        SM2UtilInstance.loadPrivateKey(privateKeyPath);

        handshakeStatus = WAIT_CLIENT_HELLO;
        this.CertFilesPath = CertFilesPath;
        sequenceNumber = 0;

        int BUFFER_SIZE = (1 << 17) + 5;
        this.in = ByteBuffer.allocate(BUFFER_SIZE);

        this.handshakeMsg = ByteBuffer.allocate(BUFFER_SIZE);

        clientWriteMACSecret = new byte[HASH_SIZE];
        serverWriteMACSecret = new byte[HASH_SIZE];
        clientWriteKey = new byte[SM4_KEY_SIZE];
        serverWriteKey = new byte[SM4_KEY_SIZE];

        sequenceNumber = acknowledgeNumber = 0;
    }

    private byte[] encrypt(byte[] text, byte packetType) throws Exception {
        byte[] iv = new byte[SM4_KEY_SIZE];
        (new SecureRandom()).nextBytes(iv);

        ByteBuffer HMACdata = ByteBuffer.allocateDirect(8 + 1 + 2 + 2 + text.length);
        HMACdata.putLong(sequenceNumber);
        HMACdata.put(packetType);
        HMACdata.putShort(PacketParser.GMSSL_VERSION);
        HMACdata.putShort((short)text.length);
        HMACdata.put(text);
        HMACdata.position(0);
        byte[] HMACdataBytes = new byte[HMACdata.remaining()];
        HMACdata.get(HMACdataBytes);

        byte[] MAC = new byte[HASH_SIZE];
        HMac hMac = new HMac(new SM3Digest());
        hMac.init(new KeyParameter(serverWriteMACSecret));
        HMAC(hMac, HMACdataBytes, MAC);

        int paddingLength = text.length % 16;
        if(paddingLength == 0) paddingLength = 16;
        byte[] padding = new byte[paddingLength];
        Arrays.fill(padding, (byte) (paddingLength - 1));

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        bos.write(text);
        bos.write(MAC);
        bos.write(padding);
        byte[] block = bos.toByteArray();
        bos.close();

        byte[] encryptedBlock = SM4Util.encrypt(block, serverWriteKey, iv);
        bos = new ByteArrayOutputStream();
        bos.write(iv);
        bos.write(encryptedBlock);
        byte[] ret = bos.toByteArray();
        bos.close();

        return ret;
    }

    private byte[] decrypt(byte[] payload, byte packetType) throws Exception {
        byte[] iv = new byte[SM4_KEY_SIZE];
        System.arraycopy(payload, 0, iv, 0, SM4_KEY_SIZE);
        byte[] data = new byte[payload.length - SM4_KEY_SIZE];
        System.arraycopy(payload, SM4_KEY_SIZE, data, 0, payload.length - SM4_KEY_SIZE);
        byte[] block = SM4Util.decrypt(data, clientWriteKey, iv);

        System.out.println("block: " + Formatter.bytesToHex(block));

        int ind = block.length;
        ind -= block[block.length - 1] + 1;

        byte[] textMAC = new byte[HASH_SIZE];
        System.arraycopy(block, ind - HASH_SIZE, textMAC, 0, HASH_SIZE);
        ind -= HASH_SIZE;

        byte[] text = new byte[ind];
        System.arraycopy(block, 0, text, 0, ind);

        ByteBuffer HMACdata = ByteBuffer.allocateDirect(8 + 1 + 2 + 2 + text.length);
        HMACdata.putLong(acknowledgeNumber);
        HMACdata.put(packetType);
        HMACdata.putShort(PacketParser.GMSSL_VERSION);
        HMACdata.putShort((short)text.length);
        HMACdata.put(text);
        HMACdata.position(0);
        byte[] HMACdataBytes = new byte[HMACdata.remaining()];
        HMACdata.get(HMACdataBytes);

        byte[] localMAC = new byte[HASH_SIZE];
        HMac hMac = new HMac(new SM3Digest());
        hMac.init(new KeyParameter(clientWriteMACSecret));
        HMAC(hMac, HMACdataBytes, localMAC);

        if(Arrays.equals(localMAC, textMAC)) return text;
        else {
            System.out.println("[decrypt]MAC check fail.");
            throw new Exception("MAC check fail.");
        }
    }

    private static void HMAC(HMac hMac, byte[] data, byte[] dst){
        hMac.update(data, 0, data.length);
        hMac.doFinal(dst, 0);
        hMac.reset();
    }

    public static void PRF(byte[] secret, byte[] label, byte[] seed, byte[] dst){

        // PRF(secret, label, seed) = P_SM3(secret, label + seed)
        // PSM3Seed = label + seed

        byte[] PSM3Seed = new byte[label.length + seed.length];
        System.arraycopy(label, 0, PSM3Seed, 0, label.length);
        System.arraycopy(seed, 0, PSM3Seed, label.length, seed.length);

        // imply P_SM3(secret, PSM3Seed)

        HMac hMac = new HMac(new SM3Digest());
        hMac.init(new KeyParameter(secret));

        byte[] A = new byte[HASH_SIZE];

        // A1 = HMAC(secret, A0 = PSM3Seed))
        HMAC(hMac, PSM3Seed, A);

        int index = 0, length = dst.length;
        while(index < length){
            // HMACData = A + PSM3Seed
            byte[] HMACData = new byte[A.length + PSM3Seed.length];
            System.arraycopy(A, 0, HMACData, 0, A.length);
            System.arraycopy(PSM3Seed, 0, HMACData, A.length, PSM3Seed.length);

            // data = HMAC(secret, HMACData = A + PSM3Seed)
            byte[] data = new byte[HASH_SIZE];
            HMAC(hMac, HMACData, data);

            // copy data to dst
            System.arraycopy(data, 0, dst, index, Math.min(data.length, dst.length - index));
            index += data.length;

            // update A
            // newA = HMAC(secret, A)
            byte[] newA = new byte[HASH_SIZE];
            HMAC(hMac, A, newA);
            A = newA;
        }
    }

    private void appendToHandshakeMsg(ByteBuffer b, int length){
        byte[] tmp = new byte[length - PacketParser.GMSSL_HEADER_LENGTH];
        b.position(b.position() - (length - PacketParser.GMSSL_HEADER_LENGTH));
        b.get(tmp);
        handshakeMsg.put(tmp);
    }

    private byte[] getHanshakeMsgHash(){
        SM3Digest SM3 = new SM3Digest();
        byte[] handshakeMsgData = new byte[handshakeMsg.position()];
        handshakeMsg.position(0);
        handshakeMsg.get(handshakeMsgData);
        SM3.update(handshakeMsgData, 0, handshakeMsgData.length);
        byte[] hash = new byte[SM3.getDigestSize()];
        SM3.doFinal(hash, 0);
        return hash;
    }

    private void calculateKey() throws IOException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, InvalidKeySpecException, BadPaddingException, InvalidKeyException {
        preMasterSecret = SM2UtilInstance.prvKetDecrypt(
                clientKeyExchange.getEncBytes()
        );

        ByteArrayOutputStream bis = new ByteArrayOutputStream();
        bis.write(clientHello.random);
        bis.write(serverHello.random);
        byte[] randoms = bis.toByteArray();
        bis.close();

        masterSecret = new byte[48];
        PRF(preMasterSecret, "master secret".getBytes(), randoms, masterSecret);

        bis = new ByteArrayOutputStream();
        bis.write(serverHello.random);
        bis.write(clientHello.random);
        randoms = bis.toByteArray();
        bis.close();

        byte[] keyBlock = new byte[HASH_SIZE * 2 + SM4_KEY_SIZE * 2];
        PRF(masterSecret, "key expansion".getBytes(), randoms, keyBlock);

        int ind = 0;
        System.arraycopy(keyBlock, ind, clientWriteMACSecret, 0, HASH_SIZE);
        ind += HASH_SIZE;
        System.arraycopy(keyBlock, ind, serverWriteMACSecret, 0, HASH_SIZE);
        ind += HASH_SIZE;
        System.arraycopy(keyBlock, ind, clientWriteKey, 0, SM4_KEY_SIZE);
        ind += SM4_KEY_SIZE;
        System.arraycopy(keyBlock, ind, serverWriteKey, 0, SM4_KEY_SIZE);

        System.out.println("key expand finish");
    }

    @Override
    public SSLEngineResult wrap(ByteBuffer [] srcs, int offset,
                                int length, ByteBuffer dst) throws SSLException {
        System.out.println("[call]wrap");
        System.out.println("[wrap]" + handshakeStatus);
        final int byteProduced;
        switch(handshakeStatus){
            case PREPARE_SERVER_HELLO:
                serverHello = new PacketParser.ServerHello();
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
                appendToHandshakeMsg(dst, byteProduced);

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
                appendToHandshakeMsg(dst, byteProduced);

                System.out.println("send certificate");
                handshakeStatus = PREPARE_SERVER_HELLO_DONE;

                return new SSLEngineResult(
                        SSLEngineResult.Status.OK,
                        SSLEngineResult.HandshakeStatus.NEED_WRAP,
                        0, byteProduced, 0
                );
            case PREPARE_SERVER_HELLO_DONE:
                byteProduced = PacketParser.ServerHelloDone.toByte(dst);
                appendToHandshakeMsg(dst, byteProduced);

                handshakeStatus = WAIT_CLIENT_KEY_EXCHANGE;
                System.out.println("send server hello done");
                return new SSLEngineResult(
                        SSLEngineResult.Status.OK,
                        SSLEngineResult.HandshakeStatus.NEED_UNWRAP,
                        0, byteProduced, 0
                );
            case PREPARE_CHANGE_CIPHER_SPEC:
                byteProduced = PacketParser.ChangeCipherSpec.toByte(dst);

                handshakeStatus = PREPARE_FINISHED;

                System.out.println("send change cipher spec");

                return new SSLEngineResult(
                        SSLEngineResult.Status.OK,
                        SSLEngineResult.HandshakeStatus.NEED_WRAP,
                        0, byteProduced, 0
                );
            case PREPARE_FINISHED:
                byte[] verifyData = new byte[12];
                PRF(masterSecret, "server finished".getBytes(), getHanshakeMsgHash(), verifyData);

                byte[] text = new byte[16];
                text[0] = 0x14;
                text[1] = text[2] = 0;
                text[3] = 0x0C;
                System.arraycopy(verifyData, 0, text, 4, 12);

                serverFinished = new PacketParser.Finished();
                try {
                    serverFinished.payload = encrypt(text, PacketParser.PacketType.HANDSHAKE);
                } catch (Exception e) {
                    e.printStackTrace();
                }

                byteProduced = serverFinished.toByte(dst);

                handshakeStatus = OK;

                System.out.println("send server finished");

                return new SSLEngineResult(
                        SSLEngineResult.Status.OK,
                        SSLEngineResult.HandshakeStatus.FINISHED,
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
            throws Exception {
        byte[] tmp;
        switch (handshakeStatus){
            case WAIT_CLIENT_HELLO:
                if (PacketParser.getPacketType(src) == PacketParser.PacketType.HANDSHAKE &&
                        PacketParser.getHandshakeType(src) == PacketParser.HandshakeType.CLIENT_HELLO){
                    System.out.println("accept client hello");
                    clientHello = PacketParser.ClientHello.fromByteBuffer(src);
                    System.out.println(clientHello);
                    handshakeStatus = PREPARE_SERVER_HELLO;

                    appendToHandshakeMsg(src, src.position());

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

                    //System.out.println("payload: " + Formatter.bytesToHex(clientKeyExchange.payload));

                    try {
                        //clientKeyExchange.getEncBytesDebug();
                        calculateKey();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }

                    appendToHandshakeMsg(src, src.position());

                    return new SSLEngineResult(
                            SSLEngineResult.Status.OK,
                            SSLEngineResult.HandshakeStatus.NEED_WRAP,
                            src.position(), 0, 0
                    );
                }
                break;
            case WAIT_CHANGE_CIPHER_SPEC:
                if (PacketParser.getPacketType(src) == PacketParser.PacketType.CHANGE_CIPHER_SPEC){
                    PacketParser.ChangeCipherSpec.fromByteBuffer(src);
                    handshakeStatus = WAIT_FINISHED;
                    System.out.println("accept change cipher spec");
                    return new SSLEngineResult(
                            SSLEngineResult.Status.OK,
                            SSLEngineResult.HandshakeStatus.NEED_WRAP,
                            src.position(), 0, 0
                    );
                }
                break;
            case WAIT_FINISHED:
                if (PacketParser.getPacketType(src) == PacketParser.PacketType.HANDSHAKE){
                    clientFinished = PacketParser.Finished.fromByteBuffer(src);

                    byte[] text = decrypt(clientFinished.payload, PacketParser.PacketType.HANDSHAKE);
                    handshakeMsg.put(text);

                    byte[] finishedMsg = new byte[12];
                    System.arraycopy(text, 4, finishedMsg, 0, 12);

                    byte[] verifyData = new byte[12];
                    PRF(masterSecret, "client finished".getBytes(), getHanshakeMsgHash(), verifyData);

                    System.out.println("finishedMsg: " + Formatter.bytesToHex(finishedMsg));
                    System.out.println("verify data: " + Formatter.bytesToHex(verifyData));
                    System.out.println("accept client finished");

                    if(Arrays.equals(finishedMsg, verifyData)){
                        System.out.println("client finished verify success");
                        handshakeStatus = PREPARE_CHANGE_CIPHER_SPEC;
                    } else {
                        System.out.println("client finished verify fail");
                        throw new SSLException("client finished verify fail");
                    }

                    return new SSLEngineResult(
                            SSLEngineResult.Status.OK,
                            SSLEngineResult.HandshakeStatus.NEED_WRAP,
                            src.position(), 0, 0
                    );
                }
                break;
            case OK:
                byte tp = PacketParser.getPacketType(src);
                PacketParser.Finished f = PacketParser.Finished.fromByteBuffer(src);
                byte[] d = decrypt(f.payload, tp);
                System.out.println("alter: " + Formatter.bytesToHex(d));
            default:
                break;
        }
        throw new SSLException("unexpected packet accepted.");
    }

    @Override
    public SSLEngineResult unwrap(ByteBuffer src,
                                  ByteBuffer [] dsts, int offset, int length) throws SSLException {
        System.out.printf("[call]unwrap, src size %d, in size %d\n", src.remaining(), in.position());

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
            } catch (Exception e) {
                System.out.println("catch exception in unwarpSingle");
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
