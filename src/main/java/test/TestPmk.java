package test;

import netty.httpsserver.Formatter;
import netty.httpsserver.SM2Util;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class TestPmk {
    final static String PRIVATE_KEY_FILE = "E:\\project\\Netty\\cert\\gmssl2\\ca.key";
    final static String payload = "044C7F06A2C25D04AFCC5A9C2FC791699F43ED1ACEFE4E66D3F891B05DFBDFF2AA8E97A9441949BB647D73A92236718B2EFA5737C80AA872234281EE596A2A981A3724849F42B15EB3154BC110DA1E43B06D8150349F7FB02AD82139E331E9548C7C79D86F0F0AF5396E67A1631FDB3058605E058A65FB3DB0985E7904D9362D08BC22CF86FC87197E7C2A489F603EA8D2";

    /**
     * bc加解密使用旧标c1||c2||c3，此方法在加密后调用，将结果转化为c1||c3||c2
     * @param c1c2c3
     * @return
     */
    public static byte[] changeC1C2C3ToC1C3C2(byte[] c1c2c3) {
        //final int c1Len = (X9ECParameters.getCurve().getFieldSize() + 7) / 8 * 2 + 1; //sm2p256v1的这个固定65。可看GMNamedCurves、ECCurve代码。
        final int c1Len = 65;
        final int c3Len = 32; //new SM3Digest().getDigestSize();
        byte[] result = new byte[c1c2c3.length];
        System.arraycopy(c1c2c3, 0, result, 0, c1Len); //c1
        System.arraycopy(c1c2c3, c1c2c3.length - c3Len, result, c1Len, c3Len); //c3
        System.arraycopy(c1c2c3, c1Len, result, c1Len + c3Len, c1c2c3.length - c1Len - c3Len); //c2
        return result;
    }


    /**
     * bc加解密使用旧标c1||c3||c2，此方法在解密前调用，将密文转化为c1||c2||c3再去解密
     * @param c1c3c2
     * @return
     */
    public static byte[] changeC1C3C2ToC1C2C3(byte[] c1c3c2) {
        //final int c1Len = (X9ECParameters.getCurve().getFieldSize() + 7) / 8 * 2 + 1; //sm2p256v1的这个固定65。可看GMNamedCurves、ECCurve代码。
        final int c1Len = 65;
        final int c3Len = 32; //new SM3Digest().getDigestSize();
        byte[] result = new byte[c1c3c2.length];
        System.arraycopy(c1c3c2, 0, result, 0, c1Len); //c1: 0->65
        System.arraycopy(c1c3c2, c1Len + c3Len, result, c1Len, c1c3c2.length - c1Len - c3Len); //c2
        System.arraycopy(c1c3c2, c1Len, result, c1c3c2.length - c3Len, c3Len); //c3
        return result;
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        System.out.println(len);
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    public static boolean test(SM2Util sm2) {
        byte[] in, out;
        in = new byte[5];
        for (int i = 0; i < 5; i++) in[i] = (byte)i;
        byte[] tmp = new byte[0];
        try {
            tmp = sm2.pubKeyEncrypt(in);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException | InvalidKeySpecException | InvalidKeyException e) {
            return false;
        }
        System.out.println("len: " + tmp.length);
        System.out.println(Formatter.bytesToHex(tmp));

        try {
            out = sm2.prvKetDecrypt(tmp);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException | InvalidKeySpecException | InvalidKeyException e) {
            return false;
        }
        for (int i = 0; i < 5; i++) if(out[i] != in[i]) return false;
        return true;
    }

    public static void main(String[] args) throws GeneralSecurityException, IOException {
        SM2Util sm2 = new SM2Util();
        sm2.loadPrivateKey(PRIVATE_KEY_FILE);
        if(!test(sm2)) return;

        byte[] packetData = hexStringToByteArray(payload);
        System.out.println("data len: " + packetData.length);

        try {
            byte[] out = sm2.prvKetDecrypt(packetData);
            System.out.println(Formatter.bytesToHex(out));
            return;
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            System.out.println("a fail");
        }

        try {
            byte[] out = sm2.prvKetDecrypt(changeC1C3C2ToC1C2C3(packetData));
            System.out.println(Formatter.bytesToHex(out));
            return;
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            System.out.println("b fail");
        }

        try {
            byte[] out = sm2.prvKetDecrypt(changeC1C2C3ToC1C3C2(packetData));
            System.out.println(Formatter.bytesToHex(out));
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            System.out.println("c fail");
        }
    }
}
