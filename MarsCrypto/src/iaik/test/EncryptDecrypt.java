package iaik.test;


import java.security.Key;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import iaik.security.provider.IAIK;
import iaik.utils.CryptoUtils;

public class EncryptDecrypt {

    public static void main(String[] args) {
        try {
            // this is the dynamic registration mentioned before
            IAIK.addAsProvider();

            byte[] data = "Hello Secure World!".getBytes("ASCII");

            byte[] tripleDesKeyBytes = new byte[24];
            (new SecureRandom()).nextBytes(tripleDesKeyBytes);
            Key tripleDesKey = new SecretKeySpec(tripleDesKeyBytes, "DESede");

            Cipher tripleDesCipher = Cipher.getInstance("DESede/CBC/PKCS5Padding", "IAIK");
            byte[] ivBytes = new byte[tripleDesCipher.getBlockSize()];
            (new SecureRandom()).nextBytes(ivBytes);
            IvParameterSpec iv = new IvParameterSpec(ivBytes);

            tripleDesCipher.init(Cipher.ENCRYPT_MODE, tripleDesKey, iv);
            byte[] cipherText = tripleDesCipher.doFinal(data);

            tripleDesCipher.init(Cipher.DECRYPT_MODE, tripleDesKey, iv);
            byte[] plainText = tripleDesCipher.doFinal(cipherText);

            if (CryptoUtils.equalsBlock(data, plainText)) {
                System.out.println("Test successful.");
            } else {
                System.err.println("Test FAILED!");
                System.exit(1);
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            System.exit(2);
        }
    }
}