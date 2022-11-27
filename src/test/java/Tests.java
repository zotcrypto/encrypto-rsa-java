import dev.ssdd.encrypto.rsa.EncryptoRSA;
import dev.ssdd.encrypto.rsa.exceptions.MessageTooBigException;
import org.junit.Test;

import java.util.Arrays;
import java.util.Scanner;

import static org.junit.Assert.assertEquals;

public class Tests {
    @Test
    public void name() {
        EncryptoRSA rsa = EncryptoRSA.init(128);
        EncryptoRSA rsa1 = EncryptoRSA.init(128);
        byte[] msg = "abc".getBytes();
        try {
            String enc = rsa.encrypt(msg, rsa1.getZotPublicKey());
            byte[] dec = rsa1.decrypt(enc);
            assertEquals(Arrays.toString(msg), Arrays.toString(dec));

            String enc1 = rsa.encryptPkcsv1_15(msg, rsa1.getZotPublicKey());
            byte[] dec1 = rsa1.decryptPkcsv1_15(enc1);
            assertEquals(Arrays.toString(msg), Arrays.toString(dec1));

            String enc2 = rsa.doubleEncrypt(msg, rsa1.getZotPublicKey());
            byte[] dec2 = rsa1.doubleDecrypt(enc2, rsa.getZotPublicKey());
            assertEquals(Arrays.toString(msg), Arrays.toString(dec2));

            String enc3 = rsa.doubleEncryptPkcsv1_15(msg, rsa1.getZotPublicKey());
            byte[] dec3 = rsa1.doubleDecryptPkcsv1_15(enc3, rsa.getZotPublicKey());
            assertEquals(Arrays.toString(msg), Arrays.toString(dec3));

        } catch (MessageTooBigException e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] args) {
        try {
            crossPlatform();
        } catch (MessageTooBigException e) {
            throw new RuntimeException(e);
        }
    }
    public static void crossPlatform() throws MessageTooBigException {
        EncryptoRSA rsa = EncryptoRSA.init(128);
        Scanner scanner = new Scanner(System.in);
        String pubkey = scanner.nextLine();

        System.out.println(rsa.getSterilizedPubKey());

        System.out.println(rsa.doubleEncryptPkcsv1_15("abc".getBytes(), rsa.deserializePublicKey(pubkey)));

    }
}
