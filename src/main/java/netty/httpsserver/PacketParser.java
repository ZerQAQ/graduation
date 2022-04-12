package netty.httpsserver;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1SequenceParser;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Vector;

import static netty.httpsserver.PacketParser.HandshakeType.SERVER_HELLO;

public class PacketParser {

    public static class PacketType {
        public static final byte CHANGE_CIPHER_SPEC = 20;
        public static final byte HANDSHAKE = 22;
        public static final byte APPLICATION_DATA = 23;
    }

    final static short GMSSL_VERSION = 0x0101;
    final static int GMSSL_HEADER_LENGTH = 5;

    public static byte getPacketType(ByteBuffer b){
        byte type = b.get(b.position());
        int version = b.getShort(b.position() + 1);
        if (version != GMSSL_VERSION) {
            System.out.println("unsupported protocol version " + String.format("0x%04x", version));
            return -1;
        }
        return type;
    }

    public static int getPacketSize(ByteBuffer b, int position){
        int length = b.getShort(position + 3);
        int version = b.getShort(position + 1);
        if (version != GMSSL_VERSION) {
            System.out.println("unsupported protocol version " + String.format("0x%04x", version));
            return -1;
        }
        return length;
    }

    public static class HandshakeType {
        public static final byte CLIENT_HELLO = 1;
        public static final byte SERVER_HELLO = 2;
        public static final byte CERTIFICATE = 11;
        public static final byte SERVER_KEY_EXCHANGE = 12;
        public static final byte SERVER_HELLO_DONE = 14;
        public static final byte CLIENT_KEY_EXCHANGE = 16;
    }

    public static int getHandshakeType(ByteBuffer b) {
       int type = b.get(b.position() + 5);
       return type;
    }

    public static class CipherSuite {
        public static final short ECC_SM4_SM3 = (short) 0xe013;
    }

    public static class CompressMethod {
        public static final byte NULL = 0;
    }

    private static void putPacketHeader(ByteBuffer b, byte type, int size) {
        b.put(type);
        b.putShort((short) GMSSL_VERSION);
        b.putShort((short) size);
    }

    private static void putHandshakeHeader(ByteBuffer b, byte type, int size) {
        b.put(type);
        put3Bytes(b, size);
    }

    private static void put3Bytes(ByteBuffer b, int val){
        b.put((byte) ((val & 0x00ff0000) >> 16) );
        b.putShort((short) (val & 0xffff));
    }

    private static void put3Bytes(ByteBuffer b, int val, int position){
        b.put(position, (byte) ((val & 0x00ff0000) >> 16) );
        b.putShort(position, (short) (val & 0xffff));
    }

    public static class ClientHello{
        public byte[] random;
        public int sessionLength;
        public byte[] sessionId;
        public int cipherSuitesLength;
        public short[] cipherSuites;
        public int compressMethodsLength;
        public byte[] compressMethods;

        public String toString() {
            StringBuilder result = new StringBuilder();
            String newLine = System.getProperty("line.separator");

            result.append( this.getClass().getName() );
            result.append( " Object {" );
            result.append(newLine);

            //determine fields declared in this class only (no fields of superclass)
            Field[] fields = this.getClass().getDeclaredFields();

            //print field names paired with their values
            for ( Field field : fields  ) {
                result.append("  ");
                try {
                    result.append( field.getName() );
                    result.append(": ");
                    //requires access to private field:
                    if(field.get(this) instanceof byte[]){
                        result.append(Formatter.bytesToHex((byte[]) field.get(this)));
                    } else if(field.get(this) instanceof short[]){
                        result.append(Formatter.shortArrayToString((short[]) field.get(this)));
                    } else {
                        result.append( field.get(this) );
                    }
                } catch ( IllegalAccessException ex ) {
                    System.out.println(ex);
                }
                result.append(newLine);
            }
            result.append("}");

            return result.toString();
        }

        public ClientHello(){

        }

        public static ClientHello fromByteBuffer(ByteBuffer b){
            // if(PacketParser.getHandshakeType(b) !=
            //        PacketParser.HandshakeType.CLIENT_HELLO) return null;
            int end = b.position() + b.getShort(b.position() + 3) + 5;
            b.position(b.position() + 11);

            ClientHello res = new ClientHello();
            res.random = new byte[32];
            b.get(res.random);
            res.sessionLength = b.get();
            res.sessionId = new byte[32];
            b.get(res.sessionId);
            res.cipherSuitesLength = b.getShort();
            res.cipherSuites = new short[res.cipherSuitesLength / 2];
            for(int i = 0; i < res.cipherSuitesLength / 2; i++){
                res.cipherSuites[i] = b.getShort();
            }
            res.compressMethodsLength = b.get();
            res.compressMethods = new byte[res.compressMethodsLength];
            for(int i = 0; i < res.compressMethodsLength; i++){
                res.compressMethods[i] = b.get();
            }

            b.position(end);
            return res;
        }
    }

    public static class ServerHello{
        public byte[] random;
        public int sessionLength;
        public byte[] sessionId;
        public int cipherSuite;
        public int compressMethod;

        private static final int SIZE = 32 + 32 + 4 + 6; // 74

        public int toByte(ByteBuffer b){
            putPacketHeader(b, PacketType.HANDSHAKE, SIZE);
            putHandshakeHeader(b, HandshakeType.SERVER_HELLO, SIZE - 4);

            b.putShort((short)GMSSL_VERSION);

            b.put(random);
            b.put((byte)sessionLength);
            b.put(sessionId);
            b.putShort((short)cipherSuite);
            b.put((byte)compressMethod);

            return SIZE + 5;
        }
    }

    public static class Certificate{
        public static final int SIZE = 7;
        Vector<X509Certificate> certChain;
        public Certificate(){
            certChain = new Vector<X509Certificate>();
        }
        public void addCert(X509Certificate cert){
            certChain.add(cert);
        }
        public int toByte(ByteBuffer b){
            int start = b.position();
            putPacketHeader(b, PacketType.HANDSHAKE, 0);
            int PacketSizeIndex = start + 3;

            b.put(HandshakeType.CERTIFICATE);

            // putEmptySize
            int HandshakePacketSizeIndex = start + 7;
            put3Bytes(b, 0);

            //putEmptyCertLength
            int CertLengthIndex= start + 10;
            put3Bytes(b, 0);

            //putCert
            int certSize = 0;
            for(X509Certificate c: certChain){
                try {
                    byte[] certByteArray = c.getEncoded();
                    certSize += 3 + certByteArray.length;
                    put3Bytes(b, certByteArray.length);
                    b.put(certByteArray);
                } catch (CertificateEncodingException e) {
                    e.printStackTrace();
                }
            }

            int end = b.position();
            int size = SIZE + certSize;

            b.putShort(PacketSizeIndex, (short) size);

            put3Bytes(b, size - 4, HandshakePacketSizeIndex);

            put3Bytes(b, certSize, CertLengthIndex);

            return end - start;
        }
    }

    public static class ServerHelloDone{
        public static final int SIZE = 4;
        public static int toByte(ByteBuffer b){
            putPacketHeader(b, PacketType.HANDSHAKE, SIZE);
            putHandshakeHeader(b, HandshakeType.SERVER_HELLO_DONE, SIZE - 4);
            return SIZE + 5;
        }
    }

    public static class ClientKeyExchange{
        short length;
        byte[] payload;

        public static ClientKeyExchange fromByteBuffer(ByteBuffer b){
            // if(getPacketType(b) != PacketType.HANDSHAKE ||
            //        getHandshakeType(b) != HandshakeType.CLIENT_KEY_EXCHANGE) return null;
            b.position(b.position() + 6);
            int length = ((0xff & b.get()) << 16) | (0xffff & b.getShort()) - 2;

            b.getShort();

            ClientKeyExchange result = new ClientKeyExchange();
            result.length = (short) length;
            result.payload = new byte[length];
            b.get(result.payload);

            return result;
        }

        public byte[] getEncBytes() throws IOException {
            int ind = 4;
            int length = payload[ind];
            ind++;
            if(length == 33) ind++;

            byte[] X = new byte[32];
            System.arraycopy(payload, ind, X, 0, 32);
            //System.out.println("Xb=" + Formatter.bytesToHex(X));
            ind += 33;

            length = payload[ind];
            ind++;
            if(length == 33) ind++;

            byte[] Y = new byte[32];
            System.arraycopy(payload, ind, Y, 0, 32);
            //System.out.println("Yb=" + Formatter.bytesToHex(Y));
            ind += 34;

            byte[] hash = new byte[32];
            System.arraycopy(payload, ind, hash, 0, 32);
            //System.out.println("hash=" + Formatter.bytesToHex(hash));
            ind += 34;

            byte[] text = new byte[48];
            System.arraycopy(payload, ind, text, 0, 48);
            //System.out.println("text=" + Formatter.bytesToHex(text));

            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            bos.write(4);
            bos.write(X);
            bos.write(Y);
            bos.write(text);
            bos.write(hash);

            return bos.toByteArray();
        }
/*
        public void getEncBytesDebug() throws IOException {
            ASN1Primitive primitive = (new ASN1InputStream(payload)).readObject();
            ASN1SequenceParser parser = ((ASN1Sequence)primitive).parser();

            ASN1Primitive XX = parser.readObject().toASN1Primitive();
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            XX.encodeTo(out);
            byte[] Xb = out.toByteArray();
            String X = XX.toString();

            String Y = parser.readObject().toASN1Primitive().toString();
            String hash = parser.readObject().toASN1Primitive().toString();
            String text = parser.readObject().toASN1Primitive().toString();

            System.out.println("X: " + X);
            System.out.println("Xb: " + Formatter.bytesToHex(Xb));
            System.out.println("Y: " + Y);
            System.out.println("hash: " + hash);
            System.out.println("text: " + text);
        }
*/
    }

    public static class ChangeCipherSpec{
        public static void fromByteBuffer(ByteBuffer b){
            b.position(b.position() + 6);
        }
        public static int toByte(ByteBuffer b){
            b.putInt(0x14010100);
            b.putShort((short) 0x0101);
            return 6;
        }
    }

    public static class Finished{
        byte[] payload;
        public static Finished fromByteBuffer(ByteBuffer b){
            b.position(b.position() + 3);
            int length = b.getShort();
            Finished ret = new Finished();
            ret.payload = new byte[length];
            b.get(ret.payload);
            return ret;
        }

        public int toByte(ByteBuffer b){
            b.putInt(0x16010100);
            b.put((byte) 0x50);
            b.put(payload);
            return 0x55;
        }
    }
}
