package com.exef.crypto;

import com.exef.utils.HexOperations;
import com.exef.utils.Logger;
import iaik.security.provider.IAIK;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class CryptoProvider {

    private byte[] buf = new byte[512];
    private Cipher _cipher;
    private String _path = "";
    private String _cryptPath;
    private String _decryptPath;
    private SecretKey _key;
    private XMLHeaderHandler _XMLHeaderHandler = new XMLHeaderHandler();
    private CryptoProperies _properies;
    private byte[] _iv;
    private KeyProvider _keyProvider;

    public CryptoProvider() {
        try {
            iaik.security.provider.IAIK.addAsProvider();
            _cipher = Cipher.getInstance("MARS/ECB/PKCS5Padding", "IAIK");
        } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException ex) {
            Logger.addMessage("Exception in ExefCryptoProvider constructor: " + ex.toString());
        } catch (Exception ex) {
            Logger.addMessage(ex.toString());
        }
    }

    private void setSecretKeyFromProvider(KeyProvider keyProvider) {
        this._key = keyProvider.getKey();
    }

    public void setPath(String path) {
        _path = path;
        try {
            _cryptPath = path.substring(0, path.lastIndexOf('.')) + ".crypted";
            _decryptPath = path.substring(0, path.lastIndexOf('.')) + ".decrypted";
        } catch (Exception ex) {
            _cryptPath = path + ".crypted";
            _decryptPath = path + ".decrypted";
        }
    }

    public void setKeyProvider(KeyProvider keyProvider) {
        this._keyProvider = keyProvider;
    }

    void setCryptoProperies(CryptoProperies properies) {
        try {
            _properies = properies;
            _XMLHeaderHandler.setCryptoProperies(properies);
            _cipher = Cipher.getInstance("MARS/" + _properies.mode + "/PKCS5Padding", "IAIK");
            if (properies.subBlockSize != null) {
                _iv = new byte[16];
            }
        } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException ex) {
            Logger.addMessage("Exception in setCryptoProperies: " + ex.toString());
        }
    }

    public void encryptFile() {
        try {
            if (_path.isEmpty()) {
                Logger.addMessage("Select file to encrypt.");
                return;
            }

            this.setSecretKeyFromProvider(_keyProvider);

            if (!_properies.mode.equalsIgnoreCase("ECB")) {
                SecureRandom sr = new SecureRandom();
                sr.nextBytes(_iv);
                _properies.iv = HexOperations.toHexString(_iv);
                _cipher.init(Cipher.ENCRYPT_MODE, _key, new IvParameterSpec(_iv));
            } else {
                _properies.subBlockSize = null;
                _cipher.init(Cipher.ENCRYPT_MODE, _key);
            }

            _properies.key = HexOperations.toHexString(_keyProvider.getCiphredKey());
            _properies.keySize = Integer.toString(_key.getEncoded().length * 8);
            _XMLHeaderHandler.makeXMLHeaderFile(_cryptPath);

            this.encrypt(new FileInputStream(_path), new FileOutputStream(_cryptPath, true));
            _iv = _cipher.getIV();
            Logger.addMessage("File encrypted to: " + _cryptPath);
        } catch (InvalidKeyException | IOException | InvalidAlgorithmParameterException ex) {
            Logger.addMessage("Exception in encryptFile(): " + ex);
        } finally {
            burnKey();
        }
    }

    public void decryptFile() {
        try {
            if (_cryptPath.isEmpty()) {
                Logger.addMessage("Select file to decrypt.");
                return;
            }
            Path fileOrg = Paths.get(_path);
            Path fileCopy = Paths.get(_path + ".tmp");
            Files.copy(fileOrg, fileCopy, StandardCopyOption.REPLACE_EXISTING);
            _path = _path + ".tmp";

            CryptoProperies properies = _XMLHeaderHandler.takeXMLHeaderFromFile(_path);
            if (properies.error != null) {
                Logger.addMessage("Error in header of choosen file!");
                return;
            }

            this.setCryptoProperies(properies);
            _keyProvider.makeKeyFromXML(properies.key, Integer.parseInt(properies.keySize));
            _key = _keyProvider.getKey();

            if (_iv != null) {
                _iv = HexOperations.toByteArray(_properies.iv);
                _cipher.init(Cipher.DECRYPT_MODE, _key, new IvParameterSpec(_iv));
            } else {
                _cipher.init(Cipher.DECRYPT_MODE, _key);
            }

            this.decrypt(new FileInputStream(_path), new FileOutputStream(_decryptPath));
            Logger.addMessage("File decrypted to: " + _decryptPath);
            this._key = null;
        } catch (Exception ex) {
            Logger.addMessage("Exception in decryptFile(): " + ex);
        } finally {
            new File(_path).delete();
            burnKey();
        }

    }

    private void encrypt(InputStream in, OutputStream out) throws IOException {
        out = new CipherOutputStream(out, _cipher);
        int numRead;
        while ((numRead = in.read(buf)) >= 0) {
            out.write(buf, 0, numRead);
        }
        in.close();
        out.close();
    }

    private void decrypt(InputStream in, OutputStream out) throws Exception {
        try {
            in = decryptFileStream(in, out);
        } catch (BadPaddingException ex) {
            Logger.addMessage("Exception in decrypt(): " + ex);
        } catch (IOException ex) {
            Logger.addMessage("Exception in decrypt(): " + ex);
            in = new FileInputStream(_cryptPath);
            int numRead;
            SecureRandom sr = new SecureRandom();
            while ((numRead = in.read(buf)) >= 0) {
                sr.nextBytes(buf);
                out.write(buf, 0, numRead);
            }
        } catch (Exception ex) {
            Logger.addMessage("Exception in decrypt(): " + ex);
        } finally {
            in.close();
            out.close();
        }
    }

    private void burnKey() {
        _key = null;
        _path = new String();
        buf = null;
        _XMLHeaderHandler = null;
        _keyProvider.burnKey();
    }

    private InputStream decryptFileStream(InputStream in, OutputStream out) throws BadPaddingException, IOException {
        in = new CipherInputStream(in, _cipher);
        int numRead;
        while ((numRead = in.read(buf)) >= 0) {
            out.write(buf, 0, numRead);
        }
        return in;
    }
}
