package dev.ssdd.encrypto.rsa;

import dev.ssdd.encrypto.rsa.exceptions.MessageTooBigException;

public class KeyPair extends KeyPairSpi {
    private final ZotPrivateKey pvt;
    private final ZotPublicKey pub;

    public KeyPair(int bitlen) {
        pvt = new ZotPrivateKey();
        pub = pvt.privInit(bitlen);
    }

    @Override
    ZotPublicKey privInit(int keylen) {
        return null;
    }

    @Override
    byte[] decrypt(byte[] val) {
        return pvt.decrypt(val);
    }

    @Override
    byte[] decryptPkcsv1_15(byte[] val) {
        return pvt.decryptPkcsv1_15(val);
    }

    @Override
    byte[] doubleDecrypt(byte[] val, ZotPublicKey publicKey) {
        return pvt.doubleDecrypt(val, publicKey);
    }

    @Override
    byte[] doubleDecryptPkcsv1_15(byte[] val, ZotPublicKey publicKey) {
        return pvt.doubleDecryptPkcsv1_15(val, publicKey);
    }

    @Override
    byte[] encrypt(byte[] val, ZotPublicKey publicKey) throws MessageTooBigException {
        return pub.encrypt(val, publicKey);
    }

    @Override
    byte[] encryptPkcsv1_15(byte[] val, ZotPublicKey publicKey) throws MessageTooBigException {
        return pub.encryptPkcsv1_15(val, publicKey);
    }

    @Override
    byte[] doubleEncrypt(byte[] val, ZotPublicKey publicKey) throws MessageTooBigException {
        return pub.doubleEncrypt(val, publicKey);
    }

    @Override
    byte[] doubleEncryptPkcsv1_15(byte[] val, ZotPublicKey publicKey) throws MessageTooBigException {
        return pub.doubleEncryptPkcsv1_15(val, publicKey);
    }

    ZotPublicKey getZotPublicKey(){
        return pub;
    }

    String sterilizedPubKey(){
        return pub.sterilizedPubKey();
    }

    ZotPublicKey deserializePublicKey(String sterilizedPubKey){
        return pub.deserializePublicKey(sterilizedPubKey);
    }

}
