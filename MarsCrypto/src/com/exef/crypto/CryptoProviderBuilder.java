package com.exef.crypto;

public class CryptoProviderBuilder {

    private CryptoProvider cryptoProvider;
    private CryptoProperies properies;

    public void createCryptoProvider() {
        properies = new CryptoProperies();
        cryptoProvider = new CryptoProvider();
    }

    public void setMode(String mode) {
        properies.mode = mode;
    }

    public void setKeySize(String keySize) {
        properies.keySize = keySize;
    }

    public void setSubBlockSize(String blockSize) {
        properies.subBlockSize = blockSize;
    }

    public CryptoProvider getCryptoProvider() {
        cryptoProvider.setCryptoProperies(properies);
        return cryptoProvider;
    }

    public void setKeyProvider(KeyProvider keyProvider) {
        cryptoProvider.setKeyProvider(keyProvider);
    }

    public void setPath(String path) {
        cryptoProvider.setPath(path);
    }
}
