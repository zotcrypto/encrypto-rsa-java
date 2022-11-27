package dev.ssdd.encrypto.rsa;

import dev.ssdd.encrypto.rsa.exceptions.MessageTooBigException;
import dev.ssdd.zot.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Base64;

public class ZotPublicKey extends KeyPairSpi{

    BigInteger e,n;
    int keylen;
    private ZotPrivateKey pk;

    @Override
    ZotPublicKey privInit(int keylen) {
        return null;
    }

    @Override
    void pubInit(BigInteger e, BigInteger n, int keylen, ZotPrivateKey pk) {
        super.pubInit(e, n, keylen, pk);
        this.e = e;
        this.n = n;
        this.keylen = keylen;
        this.pk = pk;
    }

    static boolean checkMsg(int keylen, int vallen) throws MessageTooBigException{
        final String m = "Message too big for the bitlength, try higher bitlength or use Zot AES encryption\n see: https://www.ssdd.dev/ssdd/zot/crypto/posts/aes/";
        if (keylen -11 < vallen){
            throw new MessageTooBigException(m);
        }else {
            return true;
        }
    }

    @Override
    byte[] decrypt(byte[] val) {
        throw new RuntimeException("This method should never be called in ZotPublicKey.java");
    }

    @Override
    byte[] decryptPkcsv1_15(byte[] val) {
        throw new RuntimeException("This method should never be called in ZotPublicKey.java");
    }

    @Override
    byte[] doubleDecrypt(byte[] val, ZotPublicKey publicKey) {
        throw new RuntimeException("This method should never be called in ZotPublicKey.java");
    }

    @Override
    byte[] doubleDecryptPkcsv1_15(byte[] val, ZotPublicKey publicKey) {
        throw new RuntimeException("This method should never be called in ZotPublicKey.java");
    }

    @Override
    byte[] encrypt(byte[] val, ZotPublicKey publicKey) throws MessageTooBigException {
        if (checkMsg(publicKey.keylen, val.length)){
            BigInteger msg = BigIntPlayground.convertBytesToBigInt(val);
            System.out.println("e: "+publicKey.e +" n: "+publicKey.n);
            BigInteger enc = msg.modPow(publicKey.e, publicKey.n);
            return BigIntPlayground.writeBigInt(enc);
        }else {
            return null;
        }
    }

    @Override
    byte[] encryptPkcsv1_15(byte[] val, ZotPublicKey publicKey) throws MessageTooBigException {
        val = addBytes(val);
        return this.encrypt(val, publicKey);
    }

    @Override
    byte[] doubleEncrypt(byte[] val, ZotPublicKey publicKey) throws MessageTooBigException {
        return pk.doubleEncrypt(val, publicKey);
    }

    @Override
    byte[] doubleEncryptPkcsv1_15(byte[] val, ZotPublicKey publicKey) throws MessageTooBigException {
        val = addBytes(val);
        return this.doubleEncrypt(val, publicKey);
    }
    private byte[] addBytes(byte[] val){
        SecureRandom random = new SecureRandom();
        byte[] rand = new BigInteger(126, random.nextInt(), random).toByteArray();
        ByteArrayOutputStream boOtputStream = new ByteArrayOutputStream();
        try {
            boOtputStream.write(rand);
            boOtputStream.write(val);
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }
        return boOtputStream.toByteArray();
    }

    String sterilizedPubKey(){
        JSONObject object = new JSONObject();
        object.put("pe", e.toString());
        object.put("n", n.toString());
        object.put("keylen", keylen + "");
        Base64.Encoder encoder = Base64.getEncoder();
        return encoder.encodeToString(object.toString().getBytes());
    }

    ZotPublicKey deserializePublicKey(String sterilizedPubKey) {
        Base64.Decoder decoder = Base64.getDecoder();
        String decoded = new String(decoder.decode(sterilizedPubKey.getBytes()));
        JSONObject x = new JSONObject(decoded);
        ZotPublicKey publicKey = new ZotPublicKey();
        publicKey.pubInit(x.getBigInteger("pe"), x.getBigInteger("n"), x.getInt("keylen"), pk);
        return publicKey;
    }
}
