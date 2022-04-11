package netty.httpsserver;

public class Formatter {
    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

    public static String shortArrayToString(short[] a){
        StringBuilder res = new StringBuilder();
        for(short val: a){
            res.append(Integer.toHexString((int) val & 0xffff)).append(", ");
        }
        return res.toString();
    }
}
