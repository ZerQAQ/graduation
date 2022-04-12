package netty.httpsserver;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.bouncycastle.crypto.engines.SM4Engine;
import org.bouncycastle.crypto.params.KeyParameter;

public class SM4Util
{
    /**
     *
     * @param data    明文
     * @param sm4Key  密码
     * @param iv      初始化向量
     * @return
     * @throws Exception
     */
    public static byte[] encrypt(byte[] data, byte[] sm4Key, byte[] iv) throws Exception
    {
        int length = data.length;
        ByteArrayInputStream bins = new ByteArrayInputStream(data);
        ByteArrayOutputStream bous = new ByteArrayOutputStream();
        SM4Engine engine = new SM4Engine();

        try {
            engine.init(true, new KeyParameter(sm4Key));
            for (; length > 0; length -= 16) {
                //buf存储padding后的data
                byte[] buf = new byte[16];
                byte[] out = new byte[16];

                bins.read(buf);
                for (int i = 0; i < 16; i++) {
                    //out为异或运算后的明文块
                    out[i] = ((byte) (buf[i] ^ iv[i]));
                }
                engine.processBlock(out, 0, out, 0);
                //将加密运算后的数据作为iv值
                System.arraycopy(out, 0, iv, 0, 16);
                bous.write(out);
            }
        } catch (Exception e) {
            try {
                bins.close();
                bous.close();
            } catch (IOException ioE) {
                throw ioE;
            }

            throw e;
        }

        byte[] output = bous.toByteArray();
        return output;
    }

    /**
     *
     * @param data    密文
     * @param sm4Key  密码
     * @param iv      初始化向量
     * @return
     * @throws Exception
     */
    public static byte[] decrypt(byte[] data, byte[] sm4Key, byte[] iv) throws Exception
    {
        int length = data.length;
        ByteArrayInputStream bins = new ByteArrayInputStream(data);
        ByteArrayOutputStream bous = new ByteArrayOutputStream();
        SM4Engine engine = new SM4Engine();

        try {
            engine.init(false, new KeyParameter(sm4Key));
            byte[] temp = new byte[16];
            for (; length > 0; length -= 16) {
                byte[] buf = new byte[16];
                byte[] out = new byte[16];
                try {
                    bins.read(buf);
                    System.arraycopy(buf, 0, temp, 0, 16);
                    engine.processBlock(buf, 0, out, 0);
                    for (int i = 0; i < 16; i++) {
                        out[i] = (byte) (out[i] ^ iv[i]);
                    }

                    System.arraycopy(temp, 0, iv, 0, 16);
                    bous.write(out);
                } catch (IOException e) {
                    throw e;
                }
            }
        } catch(Exception e) {
            try {
                bins.close();
                bous.close();
            } catch (IOException ioE) {
                throw ioE;
            }

            throw e;
        }

        byte[] output = bous.toByteArray();
        return output;
    }
}