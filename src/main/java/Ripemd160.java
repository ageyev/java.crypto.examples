import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.bouncycastle.util.encoders.Hex;

/*
See: https://rosettacode.org/wiki/RIPEMD-160#Java

see also: http://www.programcreek.com/java-api-examples/index.php?api=org.bouncycastle.crypto.digests.RIPEMD160Digest
*/
public class Ripemd160 {

    static String messageText = "this is a message";

    public static void main(String[] argv) throws Exception {

        byte[] r = messageText.getBytes("UTF-8");

        RIPEMD160Digest d = new RIPEMD160Digest();
        d.update(r, 0, r.length);

        byte[] o = new byte[d.getDigestSize()];
        d.doFinal(o, 0);

        // Hex.encode(o, System.out);
        // System.out.println(); // 45147c708948188cead54a10b95899a36f47dc9c

        // String digestStr = Hex.toHexString(o);
        org.apache.commons.io.output.ByteArrayOutputStream byteArrayOutputStream =
                new org.apache.commons.io.output.ByteArrayOutputStream();
        Hex.encode(o, byteArrayOutputStream);
        String digestStr = byteArrayOutputStream.toString("UTF8");
        System.out.println(digestStr); // 45147c708948188cead54a10b95899a36f47dc9c
    }

}
