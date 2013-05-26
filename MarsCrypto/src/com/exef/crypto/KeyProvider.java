package com.exef.crypto;

import com.exef.utils.HexOperations;
import com.exef.utils.Logger;
import iaik.security.provider.IAIK;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author Filip
 */
public class KeyProvider {

    private SecretKey _sessionKey;
    private byte[] _ciphredKey;
    private SecretKey _userKey;

    public KeyProvider(String secret, int keySize) {
        makeKeyFromString(secret, keySize);
    }

    public KeyProvider(String secret) {
        try {
            Security.addProvider(new IAIK());
            byte[] bytesOfSecret = secret.getBytes("UTF-8");
            MessageDigest md = MessageDigest.getInstance("MD5", "IAIK");
            byte[] secretMD5 = md.digest(bytesOfSecret);
            _userKey = new SecretKeySpec(secretMD5, "MARS");
        } catch (NoSuchAlgorithmException | NoSuchProviderException | UnsupportedEncodingException ex) {
            Logger.addMessage("Exceprion in KeyProvider constructor: " + ex);
        }
    }

    public final void makeKeyFromString(String secret, int keySize) {
        try {
            Security.addProvider(new IAIK());
            byte[] bytesOfSecret = secret.getBytes("UTF-8");
            MessageDigest md = MessageDigest.getInstance("MD5", "IAIK");
            byte[] secretMD5 = md.digest(bytesOfSecret);
            _userKey = new SecretKeySpec(secretMD5, "MARS");
            KeyGenerator keyGenerator = KeyGenerator.getInstance("MARS", "IAIK");
            keyGenerator.init(keySize);

            SecretKey generatedKey = keyGenerator.generateKey();
            byte[] encodedKeyBytes = generatedKey.getEncoded();
            _sessionKey = generatedKey;

            Logger.addMessage("Key size: " + encodedKeyBytes.length);
            
            Cipher cipher = Cipher.getInstance("MARS/ECB/NoPadding", "IAIK");
            cipher.init(Cipher.ENCRYPT_MODE, _userKey);
            _ciphredKey = cipher.doFinal(encodedKeyBytes);
        } catch (UnsupportedEncodingException | NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException | InvalidKeyException | IllegalStateException | IllegalBlockSizeException | BadPaddingException ex) {
            Logger.addMessage("Exception in ExefKeyProvider constructor: " + ex.toString());
        }
    }

    public void makeKeyFromXML(String sessionKey, int keySize) {
        try {
            _ciphredKey = HexOperations.toByteArray(sessionKey);
            Cipher cipher = Cipher.getInstance("MARS/ECB/NoPadding", "IAIK");

            cipher.init(Cipher.DECRYPT_MODE, _userKey);
            byte[] decoded = cipher.doFinal(_ciphredKey);

            _sessionKey = new SecretKeySpec(decoded, "MARS");
        } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException | InvalidKeyException | IllegalStateException | IllegalBlockSizeException | BadPaddingException ex) {
            Logger.addMessage("Exception in makeKeyFromXML" + ex);
        }
    }

    public SecretKey getKey() {
        return _sessionKey;
    }

    public byte[] getCiphredKey() {
        return _ciphredKey;
    }

    public void burnKey() {
        _sessionKey = null;
        _ciphredKey = null;
        _userKey = null;
    }

    public static void main(String[] args) {
        KeyProvider kp = new KeyProvider("Exef", 256);
        System.out.println(kp.getKey().getEncoded().length);
    }
}
