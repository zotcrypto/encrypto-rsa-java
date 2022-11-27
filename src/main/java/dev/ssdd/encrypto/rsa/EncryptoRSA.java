package dev.ssdd.encrypto.rsa;

import dev.ssdd.encrypto.rsa.exceptions.MessageTooBigException;

import java.util.Base64;

public class EncryptoRSA {
    private final KeyPair pair;

    public static EncryptoRSA init(int keylen){
        return new EncryptoRSA(new KeyPair(keylen));
    }

    public EncryptoRSA(KeyPair pair) {
        this.pair = pair;
    }

    public byte[] decrypt(String val) {
        return pair.decrypt(Base64.getDecoder().decode(val));
    }

    public byte[] decryptPkcsv1_15(String val) {
        return pair.decryptPkcsv1_15(Base64.getDecoder().decode(val));
    }

    public byte[] doubleDecrypt(String val, ZotPublicKey publicKey) {
        return pair.doubleDecrypt(Base64.getDecoder().decode(val), publicKey);
    }

    public byte[] doubleDecryptPkcsv1_15(String val, ZotPublicKey publicKey) {
        return pair.doubleDecryptPkcsv1_15(Base64.getDecoder().decode(val), publicKey);
    }

    public String encrypt(byte[] val, ZotPublicKey publicKey) throws MessageTooBigException {
        return Base64.getEncoder().encodeToString(pair.encrypt(val, publicKey));
    }

    public String encryptPkcsv1_15(byte[] val, ZotPublicKey publicKey) throws MessageTooBigException {
        return Base64.getEncoder().encodeToString(pair.encryptPkcsv1_15(val, publicKey));
    }

    public String doubleEncrypt(byte[] val, ZotPublicKey publicKey) throws MessageTooBigException {
        return Base64.getEncoder().encodeToString(pair.doubleEncrypt(val, publicKey));
    }

    public String doubleEncryptPkcsv1_15(byte[] val, ZotPublicKey publicKey) throws MessageTooBigException {
        return Base64.getEncoder().encodeToString(pair.doubleEncryptPkcsv1_15(val, publicKey));
    }

    public ZotPublicKey getZotPublicKey(){
        return pair.getZotPublicKey();
    }

    public String getSterilizedPubKey(){
        return pair.sterilizedPubKey();
    }

    public ZotPublicKey deserializePublicKey(String sterilizedPubKey){
        return pair.deserializePublicKey(sterilizedPubKey);
    }

}
