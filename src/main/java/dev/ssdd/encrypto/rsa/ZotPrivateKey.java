package dev.ssdd.encrypto.rsa;

import dev.ssdd.encrypto.rsa.exceptions.MessageTooBigException;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

public class ZotPrivateKey extends KeyPairSpi{
    private BigInteger n;
    private BigInteger d;
    int keylen;
    @Override
    ZotPublicKey privInit(int keylen) {
        SecureRandom secureRandom = new SecureRandom();
        BigInteger e = BigInteger.valueOf(65537);
        BigInteger p = new BigInteger(keylen, secureRandom.nextInt(), secureRandom);
        BigInteger q = new BigInteger(keylen, secureRandom.nextInt(), secureRandom);

        n = p.multiply(q);
        BigInteger on = (p.subtract(BigInteger.ONE)).multiply((q.subtract(BigInteger.ONE)));
        d = e.modInverse(on);
        this.keylen = keylen;
        checkResult(d, on, e, keylen);
        ZotPublicKey publicKey = new ZotPublicKey();
        publicKey.pubInit(e, n, keylen, this);
        return publicKey;
    }

    private void checkResult(BigInteger d, BigInteger on, BigInteger e, int keylen) {
        if(!BigInteger.ONE.equals(d.multiply(e).mod(on))){
            privInit(keylen);
        }
    }

    @Override
    byte[] decrypt(byte[] val) {
        BigInteger msg = BigIntPlayground.convertBytesToBigInt(val);
        BigInteger dec = msg.modPow(d, n);
        return BigIntPlayground.writeBigInt(dec);
    }

    @Override
    byte[] decryptPkcsv1_15(byte[] val) {
        byte[] x = this.decrypt(val);
        return Arrays.copyOfRange(x, 16, x.length);
    }

    @Override
    byte[] doubleDecrypt(byte[] val, ZotPublicKey publicKey) {
        BigInteger msg = BigIntPlayground.convertBytesToBigInt(val);
        BigInteger dec1 = msg.modPow(publicKey.e, publicKey.n);
        BigInteger dec = dec1.modPow(d, n);
        return BigIntPlayground.writeBigInt(dec);
    }

    @Override
    byte[] doubleDecryptPkcsv1_15(byte[] val, ZotPublicKey publicKey) {
        byte[] x = this.doubleDecrypt(val, publicKey);
        return Arrays.copyOfRange(x, 16, x.length);
    }

    @Override
    byte[] encrypt(byte[] val, ZotPublicKey publicKey) {
        //Should never be called
        throw new RuntimeException("This method should never be called in ZotPrivateKey.java");
    }

    @Override
    byte[] encryptPkcsv1_15(byte[] val, ZotPublicKey publicKey) {
        throw new RuntimeException("This method should never be called in ZotPrivateKey.java");
    }

    @Override
    byte[] doubleEncrypt(byte[] val, ZotPublicKey publicKey) throws MessageTooBigException {
        if(ZotPublicKey.checkMsg(publicKey.keylen, val.length)){
            BigInteger msg = BigIntPlayground.convertBytesToBigInt(val);
            BigInteger enc = msg.modPow(publicKey.e, publicKey.n);
            BigInteger enc1 = enc.modPow(d, n);
            return BigIntPlayground.writeBigInt(enc1);
        }
        return null;
    }

    @Override
    byte[] doubleEncryptPkcsv1_15(byte[] val, ZotPublicKey publicKey) {
        throw new RuntimeException("This method should never be called in ZotPrivateKey.java");
    }


}
