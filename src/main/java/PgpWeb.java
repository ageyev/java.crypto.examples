import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;

import java.io.*;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 *
 */
public class PgpWeb {

    static String signedMessageStr = "-----BEGIN PGP SIGNED MESSAGE-----\n" +
            "Hash: SHA256\n" +
            "\n" +
            "test 1\n" +
            "test 2\n" +
            "test 3\n" +
            "-----BEGIN PGP SIGNATURE-----\n" +
            "\n" +
            "iQEcBAEBCAAGBQJYLmkzAAoJEGjHCWlA3F4LES4H/jt1cDeRj6t0niBxjW7yvhFj\n" +
            "f0pe2bIJ0BElC5uwutHsUQRUWKozK+AGRxJBG50j7hmGmFNje+rtxbKnV9ZimUhS\n" +
            "r/KiFqeP+6noXCEo7+1d/5dnF6RDl/MLBOeheARnZtyzYl9N45K+xkAK68g+cpbY\n" +
            "QKOCsk/Qqe7G6eOPCemwo5z+Qtv3b8fGzaeMo/QzEg0C4c9H62Sa5Lg0G3uXS61Q\n" +
            "X1ydnvpB6w+cHV2BjxiADZb1hOFE+u4EBgd5BOyYZ3S/u3KbeYFnUkziU74QuVgf\n" +
            "N9bEewTEUWTrL35uSHEzHZskp+ChAYwQQlzSkfZUbveS4WgaXiqvftn/2kDDNDo=\n" +
            "=OGeS\n" +
            "-----END PGP SIGNATURE-----\n";

    static String encriptedMessageStr = "-----BEGIN PGP MESSAGE-----\n" +
            "Version: BCPG v1.47\n" +
            "\n" +
            "hQEMA2jHCWlA3F4LAQgAlUJJSWvI2sWW5YqtUQS70/p6VlcKbqsWawfIGY/oIcZU\n" +
            "RgzhGdGgzeprNBzgXfda+ecMF7agfgoYC0EjqdlQmVhPO9KRxwxjZ973D2PRJCpn\n" +
            "/NNqu7qII1rgiFJ0MuTiolLELhC4weQvFLvSNOuEtTlS3KvRjBMRi5pM3G5t1UGP\n" +
            "EdzgZnEBFpJ+CACNuAfdhSn5DCMu/51sCAAQCDw6WChrfdse7HHZ6nm8ho5iicle\n" +
            "9qiPw9NTuOnQ/4bvDK8W85+H5/eF2Ndky1QiLElgDsIRajO7NcxJndr/8BQNaaUP\n" +
            "M7q/l4DB0kYGaP8o8wt+hQKp8+QhOTJVzmtaVzBNt9JAAVeEEg4pJCSQ0pCKlAKP\n" +
            "CQ+1JQlIxrq/wY2E7eS/xIApZjaAsHOakn4ut2yxk2UyP3wwSijmQFsQo3ob+MTG\n" +
            "9g==\n" +
            "=70W7\n" +
            "-----END PGP MESSAGE-----";

    static String publicKeyStr = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "\n" +
            "mQENBFguZCMBCAC1Bh192cyYYiFl/UdPksMMIHKI1c8pMtED4ev7asoRUdsT7xpc\n" +
            "9WcwtSP+Ib5e/8A4MJDHq7As84yKAv828vJyKnvLclrrGUJqfWToRGlKV8RAwOhW\n" +
            "HlauKryplnBA5NzzAc0xrn0QXDggqkC8Q1UEJhKBbaCrDKpNz1w34BLl0m9BfnUL\n" +
            "0W1bUyzuRQMEdlNtv5RMZ/1OTJna2wbZzxKA0yl2N6KBv6fR405qrpZGBu+BgIBR\n" +
            "Ves/QzajJ1JiiX7j2WIdVH52R6zTzFRMVcq4Sa8IN67XqCmuNsQ1np6T+e6QlcZx\n" +
            "TQYgjrgN7zX8BN1QGk/vAg6dZGarPsdQUb67ABEBAAG0JHZpa3RvciBhZ2V5ZXYg\n" +
            "KHRlc3QpIDx1c2VyQGhvc3QuY29tPokBNwQTAQgAIQUCWC5kIwIbAwULCQgHAgYV\n" +
            "CAkKCwIEFgIDAQIeAQIXgAAKCRBoxwlpQNxeCyYWCACFr5UJdzTQLf1XRL/X94Ck\n" +
            "DMJ89zU9K0fmw9JhNZx6cA7nMJc7c+CEW+UotHlVkU/K63xShTNpN1VVn8Trc9CP\n" +
            "2TgYcsgStJmR26lsvJnJM3fdnIQcAdLYacp4NxyFHFwrCSvJ3gqL0yk3CcnObR7y\n" +
            "mUV6dL/Ru+zyUw5A6A1sdipds1wpVS40EWBhE5Ql+OwEDIv8U1OQtitw++NsUTZU\n" +
            "dju06CXN3/HHpkBcuE16oQx6qoDb8ILEvBIxMHzG3ivxzHmyCq5Yj6cY79lkbHss\n" +
            "xiPj4necJJVBfZrcuHgTal71gUPJ8O/kDC4XoinyjS6nNQuiIKwuSywkf/ZKANNO\n" +
            "uQENBFguZCMBCAC497DxBhjKTdp9NrisXFlxStey4N7gQ+pAcV29nnGqXKLi5Tog\n" +
            "KVMtNbgVPuod4YKB2u+NM62Qv+Ko9k7DB7ay+ExWUDCtjS5zT6tVp33COewp1ZId\n" +
            "bco0EVvKq/Mh1gfP1jW4hR9qNPD1RI6Xkr28tke+aVGevcsKk19MjczGFu9Y+d4b\n" +
            "IowbVsGGA9faC3xdIt5gzXKCYwf4yRWOA/mkL8pEKIYSqJYBH36A45K+2p0Y2cQQ\n" +
            "TaZ91CEVFK733RlLu0Rs6CqnsGjFrVSsHtSIFcjFrZZCZXGns+nfQL1cwPUqauQY\n" +
            "/UEzFVYJwYAPehQIWWSlfPM/NqzXSOEbzHv3ABEBAAGJAR8EGAEIAAkFAlguZCMC\n" +
            "GwwACgkQaMcJaUDcXgv2tgf/YlN2tM6XU8ePqCssiumNMS3bFRM9CIkeb3d+263G\n" +
            "FbsipW8nwOu9xekOemhopWGBpm6XhhLbKA4CaY7RYMaWsPqD8i2mz0gxgdJbcAnn\n" +
            "5Q9alxiKccvuwD5Y1kAuRJ4C9sGVsjK4IEcFFu/tDsLQ7S+5dXjkwMBQEi50vdQX\n" +
            "vqHD1L7tRq4OUh6w7YQ7hkIGkpk7upyJ7yM2VoqsqrB6iGLw1JVNOJsV1JQtRbIK\n" +
            "Mnqy0a8lgFh7N8vKK5Ak8lICpDbAAXPlx4RxmVrzjcq9gMaOeaXRdj0+DQ2EferR\n" +
            "ONe1zbDhsrMQgjocVATpQ4UiWdixS2X+/VzFIOJnb1rnJw==\n" +
            "=oarG\n" +
            "-----END PGP PUBLIC KEY BLOCK-----";

    static String privateKeyStr = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "\n" +
            "lQPGBFguZCMBCAC1Bh192cyYYiFl/UdPksMMIHKI1c8pMtED4ev7asoRUdsT7xpc\n" +
            "9WcwtSP+Ib5e/8A4MJDHq7As84yKAv828vJyKnvLclrrGUJqfWToRGlKV8RAwOhW\n" +
            "HlauKryplnBA5NzzAc0xrn0QXDggqkC8Q1UEJhKBbaCrDKpNz1w34BLl0m9BfnUL\n" +
            "0W1bUyzuRQMEdlNtv5RMZ/1OTJna2wbZzxKA0yl2N6KBv6fR405qrpZGBu+BgIBR\n" +
            "Ves/QzajJ1JiiX7j2WIdVH52R6zTzFRMVcq4Sa8IN67XqCmuNsQ1np6T+e6QlcZx\n" +
            "TQYgjrgN7zX8BN1QGk/vAg6dZGarPsdQUb67ABEBAAH+BwMC3r/OkDOnoY3nciHj\n" +
            "Dn7tzKILo1YLMR4fIDbSicXlvOB4q1xuwodVU4D3nz3Zh/24PlyRqikEyjNDeQlK\n" +
            "y1+VXQtYW1cr5eQDOtiFrmnCSATDr31wf6QTDhziElw+PdU2FvIAMIkSjxJ8gsU+\n" +
            "GDeerjgFOoPM51EzNxUDulACPln5gJQ211Cp/gZLGmKCRbRo11KaCnSvj0o0FN4g\n" +
            "OxlOiyza5zp1ny5dtJX6gP6cAd9WQ5AUknQpVShuJNmZk/WR36sQWpNRdR4uEmfo\n" +
            "+aDMBk8N43RN2iT67Me3qFYKYAQmOPLsGAVv2rmKjCDK1V/K96jd1ofSyjM/T4iM\n" +
            "VbS0u4tn79n4nVijx/sTvaKBcI/H1wLinMt6X3F3UBB1ic7clGdJzbCeB/9FPeg5\n" +
            "mTT9gv3v3OH9DDU9g0pHCCQ/H2uoPDNBDpyUaCo46VeqSz4TjABnxddI47Adakoo\n" +
            "zggmSg+kGTytlQnkBojX3gHXYqchUCYOwEAJPMcmwCa8ubT/44uGda+pMuEr1V4y\n" +
            "yur3tYSUbgreyGrln9ZtJlIlsP5c01TDN1oltlzazNmWDHgyOvrZXr7a8wFiotxw\n" +
            "WSM8v+myUcAtEKCZW8+9b6IPKtjZ3nYqNDSvL2GMISCYaTDtVKrmv5ik/AszminL\n" +
            "BWbtaZBPDKJ9JwlZl0jQ52MPDwDrQBjR6rUdsg2OjaJNgqNr/gG5jjg5JHuplOVf\n" +
            "Ik8YcPdd8N4yEeA4vAQih+7axNRI8948weB4QeBFujSyBO2Cos5D82xftwLWSyg8\n" +
            "oggNcFZDh+DSHTb0xcAbui7+H2mf+PUboKMNaJr9QBDFA8/spmHA62v505QAvoOs\n" +
            "z7vDWGsOAnSLN9HJBUZz49srTcdlkHbRzevPW1WuXZGVQU1+xmoU2oOn1Du2EG7c\n" +
            "YbPP52Er9JmPtCR2aWt0b3IgYWdleWV2ICh0ZXN0KSA8dXNlckBob3N0LmNvbT6J\n" +
            "ATcEEwEIACEFAlguZCMCGwMFCwkIBwIGFQgJCgsCBBYCAwECHgECF4AACgkQaMcJ\n" +
            "aUDcXgsmFggAha+VCXc00C39V0S/1/eApAzCfPc1PStH5sPSYTWcenAO5zCXO3Pg\n" +
            "hFvlKLR5VZFPyut8UoUzaTdVVZ/E63PQj9k4GHLIErSZkdupbLyZyTN33ZyEHAHS\n" +
            "2GnKeDcchRxcKwkryd4Ki9MpNwnJzm0e8plFenS/0bvs8lMOQOgNbHYqXbNcKVUu\n" +
            "NBFgYROUJfjsBAyL/FNTkLYrcPvjbFE2VHY7tOglzd/xx6ZAXLhNeqEMeqqA2/CC\n" +
            "xLwSMTB8xt4r8cx5sgquWI+nGO/ZZGx7LMYj4+J3nCSVQX2a3Lh4E2pe9YFDyfDv\n" +
            "5AwuF6Ip8o0upzULoiCsLkssJH/2SgDTTp0DxgRYLmQjAQgAuPew8QYYyk3afTa4\n" +
            "rFxZcUrXsuDe4EPqQHFdvZ5xqlyi4uU6IClTLTW4FT7qHeGCgdrvjTOtkL/iqPZO\n" +
            "wwe2svhMVlAwrY0uc0+rVad9wjnsKdWSHW3KNBFbyqvzIdYHz9Y1uIUfajTw9USO\n" +
            "l5K9vLZHvmlRnr3LCpNfTI3MxhbvWPneGyKMG1bBhgPX2gt8XSLeYM1ygmMH+MkV\n" +
            "jgP5pC/KRCiGEqiWAR9+gOOSvtqdGNnEEE2mfdQhFRSu990ZS7tEbOgqp7Boxa1U\n" +
            "rB7UiBXIxa2WQmVxp7Pp30C9XMD1KmrkGP1BMxVWCcGAD3oUCFlkpXzzPzas10jh\n" +
            "G8x79wARAQAB/gcDAvWU7bdSsvSF5+hbNDjzP1fEynSIJWqtqvy+JeKxjjOYGppH\n" +
            "mpHdKkk9O0POjW4MsNRMQ+Vrl9BOJVGaaqsKMYjSW82mbB/HLZmqtGUBfp01YNP3\n" +
            "jQni+wdCOr4P1SVqxwJ4kQvGYyts7ztyQVDdNn1giXXfq6m9lzz5a1the5oQe6il\n" +
            "XilYQ+vcP3QjOBvODuCazor0LmyXFGU61REaLp256tf50TVfUXD6yJgdzYHQHyoc\n" +
            "6DkJ5/AtSXvPUPvsNKqna9uSJw2DSxCRt8Sf/XYKGrYe3yIhPcfH6UEHsW5zjeKs\n" +
            "z6BkXvJXR2yyOoj6Di6K0ReQON0o5qyAoxALtGGcsnk+cHcFYZKn4UYwzP7KV7kc\n" +
            "8Uoe8KGJlEadW67QRVrjfhTAsSFnrRJ1p64vhdXRwmSSreGcZQlxPMK4SEeTZl0u\n" +
            "gHghdjZJzjG02f+L9x6PWlWH6CNkmV/rAzBiK3UCQc+pIWydQvwoDQxstcY/sbkZ\n" +
            "t3u2JhLOnelHJotOkWCpnnLtd680ck15kBu2gyELQPDC+mU9DVFDMHZv8M7V2K1U\n" +
            "K1/ef+rto8zKjTr32ZWEQdGw1RwLKnpV5unoQ6cx+kxJNec6A1EXKIfuKIpUepht\n" +
            "rt90scMhsa/32XwduwhKvjp3DhyUk6D170D0/ZA+xz+aXECCdluqJS/y8pSRX88J\n" +
            "VtmGs8Puhnk4ScQQFPHxz0jSetcmriK5s6oDgLbc7bAYV7UOZp5wJhkWPSI0ayGp\n" +
            "gGCcsjJOq46u8beWgblhomT+5BTLHIbgfq188lyOIMp9YnKMF0pJ2VY5lWgVmINX\n" +
            "TOEeTVdZSvsQnQzVryrpXjKtW/yi47HLAAIXk7BEOZVGSiW0SRpGVdZK8KG3IkLA\n" +
            "UdDeyTmjMI2q40JXExaxX4Eg4XYRxtIIT+pmWm93rqZLmIkBHwQYAQgACQUCWC5k\n" +
            "IwIbDAAKCRBoxwlpQNxeC/a2B/9iU3a0zpdTx4+oKyyK6Y0xLdsVEz0IiR5vd37b\n" +
            "rcYVuyKlbyfA673F6Q56aGilYYGmbpeGEtsoDgJpjtFgxpaw+oPyLabPSDGB0ltw\n" +
            "CeflD1qXGIpxy+7APljWQC5EngL2wZWyMrggRwUW7+0OwtDtL7l1eOTAwFASLnS9\n" +
            "1Be+ocPUvu1Grg5SHrDthDuGQgaSmTu6nInvIzZWiqyqsHqIYvDUlU04mxXUlC1F\n" +
            "sgoyerLRryWAWHs3y8orkCTyUgKkNsABc+XHhHGZWvONyr2Axo55pdF2PT4NDYR9\n" +
            "6tE417XNsOGysxCCOhxUBOlDhSJZ2LFLZf79XMUg4mdvWucn\n" +
            "=d9Up\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";

    static String password = "test";

    public static void main(String[] args) {

        Security.addProvider(new BouncyCastleProvider());

        try {

            byte[] encrypted = signedMessageStr.getBytes("UTF8");
            String encryptedStr = new String(encrypted, "UTF8");
            System.out.println(encryptedStr);

            byte[] encFromFile = PgpEncryption.getBytesFromFile(new File("signed.message.txt"));
            String encFromFileStr = new String(encFromFile, "UTF8");
            System.out.println(encFromFileStr);

            if (Arrays.equals(encrypted, encFromFile)) {
                System.out.println("byte[] encrypted equals byte[] encFromFile");
            } else {
                System.out.println("byte[] encrypted does not equals byte[] encFromFile");
            }
            System.out.println(Arrays.toString(encrypted));
            System.out.println(Arrays.toString(encFromFile));

            InputStream keyIn = new ByteArrayInputStream(privateKeyStr.getBytes("UTF8"));
            byte[] decryptResult = PgpEncryption
                    .decrypt(encriptedMessageStr.getBytes("UTF8"), keyIn, password.toCharArray());
            System.out.println(new String(decryptResult, "UTF8"));

            verifyText(signedMessageStr);

        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (PGPException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static String verifyText(String plainText) throws Exception {
        Pattern regex = Pattern.compile("-----BEGIN PGP SIGNED MESSAGE-----\\r?\\n.*?\\r?\\n\\r?\\n(.*)\\r?\\n(-----BEGIN PGP SIGNATURE-----\\r?\\n.*-----END PGP SIGNATURE-----)",
                Pattern.CANON_EQ | Pattern.DOTALL);
        Matcher regexMatcher = regex.matcher(plainText);
        if (regexMatcher.find()) {
            String dataText = regexMatcher.group(1);
            String signText = regexMatcher.group(2);

            ByteArrayInputStream dataIn = new ByteArrayInputStream(dataText.getBytes("UTF8"));
            ByteArrayInputStream signIn = new ByteArrayInputStream(signText.getBytes("UTF8"));

            System.out.println("\ndataText:");
            System.out.println(dataText);
            System.out.println("\nsignText:");
            System.out.println(signText);

            String result = verifyFile(dataIn, signIn);
            System.out.println(result);
            return result;
        }
        throw new Exception("Cannot recognize input data");
    }

    public static String verifyFile(
            InputStream dataIn,
            InputStream in)
            throws Exception {
        in = PGPUtil.getDecoderStream(in);
        //dataIn = PGPUtil.getDecoderStream(dataIn);
        PGPObjectFactory pgpFact = new PGPObjectFactory(in);
        PGPSignatureList p3 = null;

        Object o;

        try {
            o = pgpFact.nextObject();
            if (o == null)
                throw new Exception();
        } catch (Exception ex) {
            throw new Exception("Invalid input data");
        }

        if (o instanceof PGPCompressedData) {
            PGPCompressedData c1 = (PGPCompressedData) o;

            pgpFact = new PGPObjectFactory(c1.getDataStream());

            p3 = (PGPSignatureList) pgpFact.nextObject();
        } else
            p3 = (PGPSignatureList) o;

        int ch;

        PGPSignature sig = p3.get(0);
        // PGPPublicKey key = KeyRing.getPublicKeyByID(sig.getKeyID());
        PGPPublicKey key = readPublicKeyFromString(publicKeyStr); // <<<-----

        if (key == null)
            throw new Exception("Cannot find key 0x" + Integer.toHexString((int) sig.getKeyID()).toUpperCase() + " in the pubring");

        sig.initVerify(key, "BC");

        while ((ch = dataIn.read()) >= 0) {
            sig.update((byte) ch); //TODO migliorabile con byte[]
        }

        if (sig.verify())
            return new PrintablePGPPublicKey(key).toString();
        else
            return null;
    }

    public static PGPPublicKey readPublicKeyFromString(String armoredPublicPGPkeyBlock) throws IOException, PGPException {

        InputStream in = new ByteArrayInputStream(armoredPublicPGPkeyBlock.getBytes());

        PGPPublicKey pgpPublicKey = readPublicKey(in);

        in.close();

        return pgpPublicKey;
    }

    public static PGPPublicKey readPublicKey(InputStream iKeyStream) throws IOException {
        PGPPublicKeyRing newKey = new PGPPublicKeyRing(new ArmoredInputStream(iKeyStream));
        return newKey.getPublicKey();
    }

}
