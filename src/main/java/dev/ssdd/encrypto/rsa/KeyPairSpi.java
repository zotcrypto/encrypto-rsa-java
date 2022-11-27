package dev.ssdd.encrypto.rsa;

import dev.ssdd.encrypto.rsa.exceptions.MessageTooBigException;

import java.math.BigInteger;

public abstract class KeyPairSpi {
    abstract ZotPublicKey privInit(int keylen);
    void pubInit(BigInteger e, BigInteger n,int keylen, ZotPrivateKey pk){}

    abstract byte[] decrypt(byte[] val);
    abstract byte[] decryptPkcsv1_15(byte[] val);

    abstract byte[] doubleDecrypt(byte[] val, ZotPublicKey publicKey);
    abstract byte[] doubleDecryptPkcsv1_15(byte[] val, ZotPublicKey publicKey);

    abstract byte[] encrypt(byte[] val, ZotPublicKey publicKey) throws MessageTooBigException;
    abstract byte[] encryptPkcsv1_15(byte[] val, ZotPublicKey publicKey) throws MessageTooBigException;

    abstract byte[] doubleEncrypt(byte[] val, ZotPublicKey publicKey) throws MessageTooBigException;
    abstract byte[] doubleEncryptPkcsv1_15(byte[] val, ZotPublicKey publicKey) throws MessageTooBigException;

}
